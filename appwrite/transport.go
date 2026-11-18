package appwrite

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Transport policy.
//
// The Appwrite SDK authenticates with headers (X-Appwrite-Key,
// X-Appwrite-JWT) and Go's http.Client replays every request header on a
// redirect, including to a different origin. A compromised or misconfigured
// endpoint that answers 302 would therefore hand the function's execution key
// to whatever host it names. The client built here never follows a redirect and
// refuses anything but HTTPS (loopback or an explicit opt-in aside).
const (
	// DefaultHTTPTimeout bounds a single Appwrite API call. The SDK's own
	// default is 10s, which is short for a large page read on a cold function.
	DefaultHTTPTimeout = 30 * time.Second
	// DefaultRetryAttempts is the total number of tries for a safe read. Only
	// idempotent requests are retried, so a mutation is never replayed.
	DefaultRetryAttempts = 3
	// defaultRetryBaseDelay is the first backoff; it doubles per attempt.
	defaultRetryBaseDelay = 200 * time.Millisecond
)

var (
	// ErrInvalidEndpoint is returned for an endpoint that is not an absolute
	// http(s) URL with a host.
	ErrInvalidEndpoint = errors.New("appwrite: endpoint must be an absolute https URL")
	// ErrInsecureEndpoint is returned for a plain-HTTP endpoint outside
	// loopback when Config.AllowInsecureHTTP is not set.
	ErrInsecureEndpoint = errors.New("appwrite: endpoint must use https")
	// ErrRedirectRejected is the cause of a request that was answered with a
	// redirect. Redirects are never followed, so credentials cannot be
	// forwarded to another origin.
	ErrRedirectRejected = errors.New("appwrite: refused to follow redirect")
)

// validateEndpoint enforces the transport policy for a configured endpoint.
// HTTPS is required; plain HTTP is accepted for loopback hosts (local
// development and httptest servers) and, for anything else, only when the
// caller sets Config.AllowInsecureHTTP explicitly.
func validateEndpoint(rawEndpoint string, allowInsecure bool) error {
	parsed, err := url.Parse(rawEndpoint)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("%w: %q", ErrInvalidEndpoint, rawEndpoint)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return nil
	case "http":
		if allowInsecure || isLoopbackHost(parsed.Hostname()) {
			return nil
		}
		return fmt.Errorf("%w: %q (set Config.AllowInsecureHTTP for a trusted non-loopback test host)", ErrInsecureEndpoint, rawEndpoint)
	default:
		return fmt.Errorf("%w: %q", ErrInvalidEndpoint, rawEndpoint)
	}
}

// isLoopbackHost reports whether host is a loopback literal or name.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// newHTTPClient builds the hardened client used for every request. It keeps the
// SDK's cookie-free server behaviour, requires TLS 1.2+, and rejects redirects
// instead of replaying credentials to their target.
func newHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	var transport *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = base.Clone()
	} else {
		transport = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Timeout: timeout,
		Transport: &retryTransport{
			base:      transport,
			attempts:  DefaultRetryAttempts,
			baseDelay: defaultRetryBaseDelay,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Returning an error (rather than http.ErrUseLastResponse) makes
			// the SDK see a transport failure. ErrUseLastResponse would hand it
			// a 3xx body that it treats as a success and tries to decode.
			return fmt.Errorf("%w to %s", ErrRedirectRejected, req.URL.Scheme+"://"+req.URL.Host)
		},
	}
}

// retryTransport retries transient failures on safe requests.
//
// A transport failure (connection reset, EOF, DNS blip) leaves the caller with
// no knowledge of whether the write happened. Retrying a POST could therefore
// duplicate a row, so only GET and HEAD are replayed: Appwrite reads all use
// GET, and a failed read has no side effects. Transient statuses (429 and the
// 5xx family) are retried for the same reason; the final response is returned
// untouched so the caller still maps it.
type retryTransport struct {
	base      http.RoundTripper
	attempts  int
	baseDelay time.Duration
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.base == nil {
		t.base = http.DefaultTransport
	}
	attempts := t.attempts
	if attempts < 1 {
		attempts = 1
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return t.base.RoundTrip(req)
	}

	var lastErr error
	for attempt := 1; ; attempt++ {
		if attempt > 1 {
			if err := sleep(req, t.delay(attempt-1)); err != nil {
				return nil, err
			}
		}
		resp, err := t.base.RoundTrip(req)
		if err == nil && !retryableStatus(resp.StatusCode) {
			return resp, nil
		}
		if err != nil {
			// A cancelled request or an exhausted attempt budget is final.
			if req.Context().Err() != nil {
				return nil, err
			}
			lastErr = err
		} else {
			drain(resp)
			lastErr = fmt.Errorf("%s %s: status %d", req.Method, req.URL.Path, resp.StatusCode)
		}
		if attempt >= attempts {
			return nil, lastErr
		}
	}
}

func (t *retryTransport) delay(attempt int) time.Duration {
	base := t.baseDelay
	if base <= 0 {
		base = defaultRetryBaseDelay
	}
	return base << (attempt - 1)
}

func retryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// drain closes a response whose body is being discarded so the connection can
// be reused.
func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
}

// sleep waits for d unless the request is cancelled first.
func sleep(req *http.Request, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-req.Context().Done():
		return req.Context().Err()
	}
}
