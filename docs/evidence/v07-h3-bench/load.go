// Command load is the HTTP/3 load generator used by the S-H3-01/S-H3-02
// evidence in docs/evidence/v07-h3-bench.md.
//
// It is a real client: quic-go's QUIC transport plus its HTTP/3 (RFC 9114)
// implementation and QPACK, verified TLS (the fixture CA is passed with
// -cacert), one QUIC connection per -conns and -streams concurrent request
// streams per connection. It is not the system under test; the evidence
// declares its headroom (its own CPU seconds) and calibrates it against a
// local sink of the same binary before the campaign.
//
// Modes:
//
//	load       S-H3-01: closed-loop GETs for -duration over -conns connections
//	           with -streams streams each; per-request latency is measured from
//	           just before the request is written until the body is fully read.
//	handshake  S-H3-02: fresh QUIC handshakes (no session resumption, no 0-RTT)
//	           with -conns concurrent dials, each closed immediately after the
//	           handshake completes.
//	sink       local HTTP/3 server returning a fixed 1 KiB body, used to
//	           calibrate the generator's own ceiling.
//
// Output (stdout, or -json): one JSON object with the raw measurements.
// Diagnostics go to stderr.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const bodySize = 1024

type report struct {
	Mode         string            `json:"mode"`
	Target       string            `json:"target"`
	Conns        int               `json:"conns"`
	Streams      int               `json:"streams,omitempty"`
	WarmupS      float64           `json:"warmup_s"`
	DurationS    float64           `json:"duration_s"`
	WallS        float64           `json:"wall_s"`
	Requests     int64             `json:"requests"`
	OK           int64             `json:"ok"`
	Errors       int64             `json:"errors"`
	StatusCodes  map[int]int64     `json:"status_codes"`
	Bytes        int64             `json:"bytes"`
	RPS          float64           `json:"rps"`
	Latency      *summary          `json:"latency_ms,omitempty"`
	Connect      *summary          `json:"connect_ms,omitempty"`
	Handshakes   int64             `json:"handshakes,omitempty"`
	HandshakesPS float64           `json:"handshakes_per_sec,omitempty"`
	Handshake    *summary          `json:"handshake_ms,omitempty"`
	Sanity       string            `json:"sanity"`
	ErrorSample  []string          `json:"error_sample,omitempty"`
	GenCPUMS     float64           `json:"generator_cpu_seconds"`
	GenCPUPct    float64           `json:"generator_cpu_pct_one_core"`
	Extra        map[string]string `json:"extra,omitempty"`
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
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read ca: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("no certificate found in -cacert")
		}
	} else {
		return nil, errors.New("-cacert is required: the benchmark verifies TLS, it does not skip it")
	}
	return &tls.Config{
		RootCAs:    pool,
		ServerName: sni,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"},
	}, nil
}

func quicConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
		KeepAlivePeriod:      10 * time.Second,
	}
}

func main() {
	mode := flag.String("mode", "load", "load | handshake | sink | origin")
	target := flag.String("url", "", "https://host:port/path")
	conns := flag.Int("conns", 8, "QUIC connections (load) or concurrent dials (handshake)")
	streams := flag.Int("streams", 16, "concurrent request streams per connection (load)")
	warmup := flag.Duration("warmup", 3*time.Second, "warm-up before samples are recorded")
	duration := flag.Duration("duration", 15*time.Second, "measured window")
	caFile := flag.String("cacert", "", "PEM CA that signed the server certificate")
	sni := flag.String("sni", "localhost", "TLS ServerName (also used for verification)")
	outFile := flag.String("json", "", "write the JSON report here instead of stdout")
	addr := flag.String("addr", ":9443", "listen address (mode=sink or mode=origin)")
	certFile := flag.String("cert", "", "sink certificate")
	keyFile := flag.String("key", "", "sink key")
	flag.Parse()

	var err error
	switch *mode {
	case "sink":
		err = runSink(*addr, *certFile, *keyFile)
	case "origin":
		err = runOrigin(*addr)
	default:
		var rep *report
		rep, err = run(*mode, *target, *conns, *streams, *warmup, *duration, *caFile, *sni)
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
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(mode, rawURL string, conns, streams int, warmup, duration time.Duration,
	caFile, sni string) (*report, error) {
	if rawURL == "" {
		return nil, errors.New("-url is required")
	}
	tlsConf, err := tlsConfig(caFile, sni)
	if err != nil {
		return nil, err
	}
	if conns < 1 {
		return nil, errors.New("-conns must be >= 1")
	}
	if mode == "handshake" {
		return runHandshake(rawURL, conns, warmup, duration, tlsConf)
	}
	if mode != "load" {
		return nil, fmt.Errorf("unknown -mode %q", mode)
	}
	if streams < 1 {
		return nil, errors.New("-streams must be >= 1")
	}
	return runLoad(rawURL, conns, streams, warmup, duration, tlsConf)
}

func runLoad(rawURL string, conns, streams int, warmup, duration time.Duration,
	tlsConf *tls.Config) (*report, error) {
	cpuStart := cpuSeconds()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type worker struct {
		samples []time.Duration
		reqs    int64
		ok      int64
		errs    int64
	}
	var (
		mu       sync.Mutex
		statuses = map[int]int64{}
		errsSeen []string
		bytesHit int64
	)
	var measure, stop atomic.Bool

	clients := make([]*http.Client, 0, conns)
	transports := make([]*http3.Transport, 0, conns)
	for i := 0; i < conns; i++ {
		tr := &http3.Transport{
			TLSClientConfig:    tlsConf.Clone(),
			QUICConfig:         quicConfig(),
			DisableCompression: true,
		}
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
			tr.Close()
		}
	}()

	// One sanity request per client verifies TLS, h3 and the 1 KiB contract
	// before the measurement starts; a failure aborts instead of measuring air.
	sanity := "ok"
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
		if resp.StatusCode != http.StatusOK || n != bodySize {
			return nil, fmt.Errorf("sanity request on connection %d: status %d body %d (want 200/%d)",
				i, resp.StatusCode, n, bodySize)
		}
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
				if resp.StatusCode == http.StatusOK && n == bodySize {
					w.ok++
					atomic.AddInt64(&bytesHit, n)
				} else {
					w.errs++
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
		samples []time.Duration
		reqs    int64
		ok      int64
		errs    int64
	)
	for _, w := range all {
		samples = append(samples, w.samples...)
		reqs += w.reqs
		ok += w.ok
		errs += w.errs
	}
	window := measureEnd.Sub(measureStart).Seconds()
	rep := &report{
		Mode:        "load",
		Target:      rawURL,
		Conns:       conns,
		Streams:     streams,
		WarmupS:     warmup.Seconds(),
		DurationS:   duration.Seconds(),
		WallS:       time.Since(start).Seconds(),
		Requests:    reqs,
		OK:          ok,
		Errors:      errs,
		StatusCodes: statuses,
		Bytes:       atomic.LoadInt64(&bytesHit),
		RPS:         float64(len(samples)) / window,
		Latency:     summarize(samples),
		Sanity:      sanity,
		ErrorSample: errsSeen,
		GenCPUMS:    (cpuEnd - cpuStart) * 1000,
		GenCPUPct:   (cpuEnd - cpuStart) / time.Since(start).Seconds() * 100,
	}
	if rep.Latency == nil {
		return nil, errors.New("no successful measured request")
	}
	return rep, nil
}

func runHandshake(rawURL string, conns int, warmup, duration time.Duration,
	tlsConf *tls.Config) (*report, error) {
	host := rawURL
	if u, err := urlHost(rawURL); err == nil {
		host = u
	}
	cpuStart := cpuSeconds()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The endpoint must actually serve h3: one request on a fresh connection
	// before the handshake flood, so a "handshake OK, no request" server does
	// not pass as measured.
	{
		tr := &http3.Transport{TLSClientConfig: tlsConf.Clone(), QUICConfig: quicConfig()}
		c := &http.Client{Transport: tr}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := c.Do(req)
		if err != nil {
			return nil, fmt.Errorf("sanity request: %w", err)
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		tr.Close()
		if resp.StatusCode != http.StatusOK || n != bodySize {
			return nil, fmt.Errorf("sanity request: status %d body %d (want 200/%d)",
				resp.StatusCode, n, bodySize)
		}
	}

	var measure, stop atomic.Bool
	var (
		mu        sync.Mutex
		hsSamples []time.Duration
		hsOK      int64
		hsErr     int64
		errsSeen  []string
	)
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				hsStart := time.Now()
				conn, err := quic.DialAddr(ctx, host, tlsConf.Clone(), quicConfig())
				elapsed := time.Since(hsStart)
				if err != nil {
					atomic.AddInt64(&hsErr, 1)
					mu.Lock()
					if len(errsSeen) < 5 {
						errsSeen = append(errsSeen, err.Error())
					}
					mu.Unlock()
					continue
				}
				atomic.AddInt64(&hsOK, 1)
				if measure.Load() {
					mu.Lock()
					hsSamples = append(hsSamples, elapsed)
					mu.Unlock()
				}
				conn.CloseWithError(0, "")
			}
		}()
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

	window := measureEnd.Sub(measureStart).Seconds()
	rep := &report{
		Mode:         "handshake",
		Target:       rawURL,
		Conns:        conns,
		WarmupS:      warmup.Seconds(),
		DurationS:    duration.Seconds(),
		WallS:        time.Since(start).Seconds(),
		Handshakes:   int64(len(hsSamples)),
		HandshakesPS: float64(len(hsSamples)) / window,
		Handshake:    summarize(hsSamples),
		Errors:       atomic.LoadInt64(&hsErr),
		Sanity:       "ok",
		ErrorSample:  errsSeen,
		GenCPUMS:     (cpuEnd - cpuStart) * 1000,
		GenCPUPct:    (cpuEnd - cpuStart) / time.Since(start).Seconds() * 100,
	}
	if rep.Handshake == nil {
		return nil, errors.New("no successful handshake in the measured window")
	}
	return rep, nil
}

// urlHost extracts host:port from an https URL without importing net/url's
// full surface in the hot path.
func urlHost(raw string) (string, error) {
	rest := raw
	if len(rest) > 8 && rest[:8] == "https://" {
		rest = rest[8:]
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			return rest[:i], nil
		}
	}
	if rest == "" {
		return "", errors.New("empty URL")
	}
	return rest, nil
}

// runOrigin is the versioned HTTP/1.1 origin both proxies forward to: one
// fixed 1 KiB body with Content-Length over keep-alive, no TLS, no logging in
// the hot path. It is part of the harness (the measured component is the
// proxy), and the evidence declares its CPU with the same probe as the
// proxies so an origin bottleneck cannot be mistaken for a proxy result.
func runOrigin(addr string) error {
	body := make([]byte, bodySize)
	for i := range body {
		body[i] = 'x'
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprint(bodySize))
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	})
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	fmt.Fprintln(os.Stderr, "origin listening on", addr)
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

func runSink(addr, certFile, keyFile string) error {
	if certFile == "" || keyFile == "" {
		return errors.New("-cert and -key are required in sink mode")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	body := make([]byte, bodySize)
	for i := range body {
		body[i] = 'x'
	}
	srv := &http3.Server{
		Addr:      addr,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		QUICConfig: &quic.Config{
			MaxIdleTimeout:  30 * time.Second,
			KeepAlivePeriod: 10 * time.Second,
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", fmt.Sprint(bodySize))
			w.WriteHeader(http.StatusOK)
			w.Write(body)
		}),
	}
	fmt.Fprintln(os.Stderr, "sink listening on", addr)
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
