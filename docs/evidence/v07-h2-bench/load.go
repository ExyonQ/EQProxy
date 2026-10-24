// Command load is the HTTP/2 load generator used by the S-H2-01/S-H2-02
// evidence in docs/evidence/v07-h2-bench.md.
//
// It is a real client: Go's HTTP/2 implementation (golang.org/x/net/http2)
// over TLS with ALPN `h2`, verified against the fixture CA, one transport
// (connection) per -conns and -streams concurrent request streams per
// connection. `StrictMaxConcurrentStreams` pins each transport to a single
// connection instead of silently opening more when the server's advertised
// limit is reached, so the scenario's "100 streams/connection" is what the
// server actually sees.
//
// Modes:
//
//	load    closed-loop GETs for -duration over -conns connections with
//	        -streams streams each, -payload bytes per response; per-request
//	        latency is measured from just before Do until the body is read and
//	        its length and HTTP/2 protocol are validated.
//	sink    local HTTP/2 server (same binary) returning -payload bytes, used
//	        to calibrate the generator's own ceiling.
//	origin  the versioned HTTP/1.1 origin both proxies forward to: one fixed
//	        -payload body with Content-Length over keep-alive, no TLS, no logs.
//
// Output (stdout, or -json): one JSON object with the raw measurements.
// Diagnostics go to stderr.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/http2"
)

type report struct {
	Mode        string            `json:"mode"`
	Target      string            `json:"target"`
	Conns       int               `json:"conns"`
	Streams     int               `json:"streams,omitempty"`
	Payload     int               `json:"payload_bytes"`
	WarmupS     float64           `json:"warmup_s"`
	DurationS   float64           `json:"duration_s"`
	WallS       float64           `json:"wall_s"`
	Requests    int64             `json:"requests"`
	OK          int64             `json:"ok"`
	Errors      int64             `json:"errors"`
	StatusCodes map[int]int64     `json:"status_codes"`
	Proto       string            `json:"proto"`
	Bytes       int64             `json:"bytes"`
	RPS         float64           `json:"rps"`
	MiBPerSec   float64           `json:"mib_per_sec"`
	Latency     *summary          `json:"latency_ms,omitempty"`
	Sanity      string            `json:"sanity"`
	ErrorSample []string          `json:"error_sample,omitempty"`
	GenCPUMS    float64           `json:"generator_cpu_seconds"`
	GenCPUPct   float64           `json:"generator_cpu_pct_one_core"`
	Extra       map[string]string `json:"extra,omitempty"`
}

type summary struct {
	Count   int      `json:"count"`
	Min     float64  `json:"min"`
	P50     float64  `json:"p50"`
	P95     float64  `json:"p95"`
	P99     float64  `json:"p99"`
	Max     float64  `json:"max"`
	Mean    float64  `json:"mean"`
	Buckets []bucket `json:"histogram"`
}

type bucket struct {
	UpperMS float64 `json:"upper_ms"` // 0 means +Inf
	Count   int     `json:"count"`
}

var bucketBounds = []float64{0.5, 1, 2, 3, 5, 7.5, 10, 15, 20, 30, 50, 75, 100, 200, 500}

func summarize(samples []time.Duration) *summary {
	if len(samples) == 0 {
		return nil
	}
	ms := make([]float64, len(samples))
	var sum float64
	for i, d := range samples {
		ms[i] = float64(d) / 1e6
		sum += ms[i]
	}
	sort.Float64s(ms)
	at := func(q float64) float64 {
		idx := int(q * float64(len(ms)-1))
		return ms[idx]
	}
	s := &summary{
		Count: len(ms),
		Min:   ms[0],
		P50:   at(0.50),
		P95:   at(0.95),
		P99:   at(0.99),
		Max:   ms[len(ms)-1],
		Mean:  sum / float64(len(ms)),
	}
	counts := make([]int, len(bucketBounds)+1)
	for _, v := range ms {
		i := 0
		for ; i < len(bucketBounds) && v > bucketBounds[i]; i++ {
		}
		counts[i]++
	}
	for i, c := range counts {
		upper := 0.0
		if i < len(bucketBounds) {
			upper = bucketBounds[i]
		}
		s.Buckets = append(s.Buckets, bucket{UpperMS: upper, Count: c})
	}
	return s
}

func cpuSeconds() float64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6 +
		float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6
}

func tlsConfig(caFile, sni string) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if caFile == "" {
		return nil, errors.New("-cacert is required: the benchmark verifies TLS, it does not skip it")
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no certificate found in -cacert")
	}
	return &tls.Config{
		RootCAs:    pool,
		ServerName: sni,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"},
	}, nil
}

func newTransport(tlsConf *tls.Config) *http2.Transport {
	return &http2.Transport{
		TLSClientConfig: tlsConf.Clone(),
		AllowHTTP:       false,
		// One connection per transport: with 100 streams on a server that
		// advertises 100 (HAProxy) or 128 (EQProxy) the extra streams queue
		// instead of being spread over an unmeasured second connection.
		StrictMaxConcurrentStreams: true,
		DisableCompression:         true,
	}
}

func main() {
	mode := flag.String("mode", "load", "load | sink | origin")
	target := flag.String("url", "", "https://host:port/path")
	conns := flag.Int("conns", 4, "HTTP/2 connections (load)")
	streams := flag.Int("streams", 100, "concurrent request streams per connection (load)")
	payload := flag.Int("payload", 1024, "response body size in bytes")
	warmup := flag.Duration("warmup", 3*time.Second, "warm-up before samples are recorded")
	duration := flag.Duration("duration", 15*time.Second, "measured window")
	caFile := flag.String("cacert", "", "PEM CA that signed the server certificate")
	sni := flag.String("sni", "localhost", "TLS ServerName (also used for verification)")
	outFile := flag.String("json", "", "write the JSON report here instead of stdout")
	addr := flag.String("addr", ":9443", "listen address (mode=sink or mode=origin)")
	certFile := flag.String("cert", "", "sink certificate")
	keyFile := flag.String("key", "", "sink key")
	flag.Parse()

	if *payload < 1 {
		fmt.Fprintln(os.Stderr, "error: -payload must be >= 1")
		os.Exit(2)
	}

	var err error
	switch *mode {
	case "sink":
		err = runSink(*addr, *certFile, *keyFile)
	case "origin":
		err = runOrigin(*addr)
	case "load":
		var rep *report
		rep, err = runLoad(*target, *conns, *streams, *payload, *warmup, *duration, *caFile, *sni)
		if err == nil {
			var data []byte
			data, err = json.MarshalIndent(rep, "", "  ")
			if err == nil {
				data = append(data, '\n')
				if *outFile != "" {
					err = os.WriteFile(*outFile, data, 0o644)
				} else {
					_, err = os.Stdout.Write(data)
				}
			}
		}
	default:
		err = fmt.Errorf("unknown -mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runLoad(rawURL string, conns, streams, payload int, warmup, duration time.Duration,
	caFile, sni string) (*report, error) {
	if rawURL == "" {
		return nil, errors.New("-url is required")
	}
	if conns < 1 || streams < 1 {
		return nil, errors.New("-conns and -streams must be >= 1")
	}
	tlsConf, err := tlsConfig(caFile, sni)
	if err != nil {
		return nil, err
	}
	cpuStart := cpuSeconds()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type worker struct {
		samples []time.Duration
		bytes   int64 // body bytes of the measured window only
		reqs    int64
		ok      int64
		errs    int64
	}
	var (
		mu       sync.Mutex
		statuses = map[int]int64{}
		errsSeen []string
		bytesHit int64
		proto    string
	)
	var measure, stop atomic.Bool

	transports := make([]*http2.Transport, 0, conns)
	clients := make([]*http.Client, 0, conns)
	for i := 0; i < conns; i++ {
		tr := newTransport(tlsConf)
		transports = append(transports, tr)
		clients = append(clients, &http.Client{
			Transport: tr,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		})
	}
	defer func() {
		for _, tr := range transports {
			tr.CloseIdleConnections()
		}
	}()

	// One sanity request per transport verifies TLS, ALPN h2, HTTP/2 framing
	// and the payload contract before the measurement starts; a failure aborts
	// instead of measuring air.
	for i, c := range clients {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := c.Do(req)
		if err != nil {
			return nil, fmt.Errorf("sanity request on connection %d: %w", i, err)
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || n != int64(payload) || resp.ProtoMajor != 2 {
			return nil, fmt.Errorf(
				"sanity request on connection %d: status %d body %d proto %s (want 200/%d/HTTP/2)",
				i, resp.StatusCode, n, resp.Proto, payload)
		}
		proto = resp.Proto
	}

	start := time.Now()
	workers := conns * streams
	var wg sync.WaitGroup
	all := make([]*worker, workers)
	for i := 0; i < workers; i++ {
		w := &worker{}
		all[i] = w
		wg.Add(1)
		go func(w *worker, client *http.Client) {
			defer wg.Done()
			for !stop.Load() {
				reqStart := time.Now()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
				if err != nil {
					continue
				}
				resp, err := client.Do(req)
				var n int64
				if err == nil {
					n, err = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				elapsed := time.Since(reqStart)
				w.reqs++
				if err != nil {
					w.errs++
					mu.Lock()
					if len(errsSeen) < 5 {
						errsSeen = append(errsSeen, err.Error())
					}
					mu.Unlock()
					continue
				}
				mu.Lock()
				statuses[resp.StatusCode]++
				mu.Unlock()
				if resp.StatusCode == http.StatusOK && n == int64(payload) && resp.ProtoMajor == 2 {
					w.ok++
					atomic.AddInt64(&bytesHit, n)
					if measure.Load() {
						w.bytes += n
					}
				} else {
					w.errs++
					mu.Lock()
					if len(errsSeen) < 5 {
						errsSeen = append(errsSeen,
							fmt.Sprintf("status %d body %d proto %s", resp.StatusCode, n, resp.Proto))
					}
					mu.Unlock()
				}
				if measure.Load() {
					w.samples = append(w.samples, elapsed)
				}
			}
		}(w, clients[i/streams])
	}

	time.Sleep(warmup)
	measureStart := time.Now()
	measure.Store(true)
	time.Sleep(duration)
	measureEnd := time.Now()
	measure.Store(false)
	stop.Store(true)
	wg.Wait()
	cpuEnd := cpuSeconds()

	var (
		samples    []time.Duration
		reqs       int64
		ok         int64
		errs       int64
		bytesTotal int64
	)
	for _, w := range all {
		samples = append(samples, w.samples...)
		reqs += w.reqs
		ok += w.ok
		errs += w.errs
		bytesTotal += w.bytes
	}
	window := measureEnd.Sub(measureStart).Seconds()
	rep := &report{
		Mode:        "load",
		Target:      rawURL,
		Conns:       conns,
		Streams:     streams,
		Payload:     payload,
		WarmupS:     warmup.Seconds(),
		DurationS:   duration.Seconds(),
		WallS:       time.Since(start).Seconds(),
		Requests:    reqs,
		OK:          ok,
		Errors:      errs,
		StatusCodes: statuses,
		Proto:       proto,
		Bytes:       bytesTotal,
		RPS:         float64(len(samples)) / window,
		MiBPerSec:   float64(bytesTotal) / window / (1 << 20),
		Latency:     summarize(samples),
		Sanity:      "ok",
		ErrorSample: errsSeen,
		GenCPUMS:    (cpuEnd - cpuStart) * 1000,
		GenCPUPct:   (cpuEnd - cpuStart) / time.Since(start).Seconds() * 100,
	}
	if rep.Latency == nil {
		return nil, errors.New("no successful measured request")
	}
	return rep, nil
}

// runOrigin is the versioned HTTP/1.1 origin both proxies forward to: one
// fixed payload with Content-Length over keep-alive, no TLS, no logging in the
// hot path. It is part of the harness (the measured component is the proxy),
// and the evidence declares its CPU with the same probe as the proxies so an
// origin bottleneck cannot be mistaken for a proxy result.
// maxPayload bounds the path-addressed bodies both fixtures serve: /1024 and
// /1048576 are the S-H2-01 and S-H2-02 contracts, / is 1 KiB.
const maxPayload = 8 << 20

// sizeFromPath turns GET /<bytes> into the exact body size; 0 means the path
// is not a size the fixture serves (a 404, never a guessed body).
func sizeFromPath(path string) int {
	s := strings.TrimPrefix(path, "/")
	if s == "" {
		return 1024
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > maxPayload {
		return 0
	}
	return n
}

func runOrigin(addr string) error {
	body := bytes.Repeat([]byte("x"), maxPayload)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := sizeFromPath(r.URL.Path)
		if n == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			w.Write(body[:n])
		}
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	fmt.Fprintln(os.Stderr, "origin listening on", addr, "bodies /<bytes>")
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		return err
	case <-sig:
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}

// runSink is a real HTTP/2 server over TLS (ALPN h2) of the same binary. The
// generator is calibrated against it; the slower side is the ceiling, so the
// calibration is a lower bound of what the client can push.
func runSink(addr, certFile, keyFile string) error {
	if certFile == "" || keyFile == "" {
		return errors.New("-cert and -key are required in sink mode")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	body := bytes.Repeat([]byte("x"), maxPayload)
	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := sizeFromPath(r.URL.Path)
			if n == 0 {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", strconv.Itoa(n))
			w.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				w.Write(body[:n])
			}
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h2"},
		},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "sink listening on", addr, "bodies /<bytes>")
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ServeTLS(ln, certFile, keyFile) }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		return err
	case <-sig:
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}
