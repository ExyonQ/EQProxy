// Command interop-quic-go is the second independent HTTP/3 client used by
// docs/evidence/v07-http3/run.py. It speaks HTTP/3 with quic-go's own QUIC
// stack (not quinn/h3, the library inside eqproxy), so a passing journey
// proves the proxy interoperates with a separate implementation.
//
// It only performs requests and reports what came back as JSON; every
// assertion stays in the Python orchestrator, next to the aioquic checks.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go/http3"
)

type result struct {
	Journey  string              `json:"journey"`
	Status   int                 `json:"status"`
	Headers  map[string][]string `json:"headers"`
	BodyB64  string              `json:"body_b64"`
	Trailers map[string][]string `json:"trailers"`
	Error    string              `json:"error,omitempty"`
}

// readerOnly hides the concrete reader type from net/http so the request has
// no known content length, exactly like the aioquic journey that sends 256 KiB
// without `content-length`.
type readerOnly struct{ io.Reader }

func fetch(client *http.Client, name, method, url string, headers map[string]string, body []byte, unknownLength bool) result {
	var reader io.Reader
	if body != nil {
		if unknownLength {
			reader = readerOnly{bytes.NewReader(body)}
		} else {
			reader = bytes.NewReader(body)
		}
	}
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		return result{Journey: name, Error: err.Error()}
	}
	// The transport dials the URL's address; the authority the proxy must
	// translate to `host` is the same name the aioquic client uses.
	request.Host = "localhost"
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return result{Journey: name, Error: err.Error()}
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		return result{Journey: name, Status: response.StatusCode, Error: err.Error()}
	}
	trailers := map[string][]string{}
	for key, values := range response.Trailer {
		trailers[key] = values
	}
	return result{
		Journey:  name,
		Status:   response.StatusCode,
		Headers:  response.Header,
		BodyB64:  base64.StdEncoding.EncodeToString(payload),
		Trailers: trailers,
	}
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "proxy address")
	certPath := flag.String("cert", "", "PEM certificate to trust")
	flag.Parse()

	pem, err := os.ReadFile(*certPath)
	if err != nil {
		fatal("read cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		fatal("no certificate found in %s", *certPath)
	}
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}
	base := "https://" + *addr

	upload := make([]byte, 256*1024)
	for i := range upload {
		upload[i] = byte(i % 251)
	}
	journeys := []struct {
		name          string
		method        string
		path          string
		headers       map[string]string
		body          []byte
		unknownLength bool
	}{
		{"get", http.MethodGet, "/hello", nil, nil, false},
		{"post_streaming", http.MethodPost, "/echo", nil, upload, true},
		{"chunked_trailers", http.MethodGet, "/trailers", nil, nil, false},
		{"compression", http.MethodGet, "/compress", map[string]string{"Accept-Encoding": "gzip"}, nil, false},
		{"direct_rule", http.MethodGet, "/shed", nil, nil, false},
	}
	results := make([]result, 0, len(journeys))
	for _, journey := range journeys {
		results = append(results, fetch(client, journey.name, journey.method, base+journey.path, journey.headers, journey.body, journey.unknownLength))
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		fatal("encode: %v", err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
