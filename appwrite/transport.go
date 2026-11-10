package appwrite

import (
	"crypto/tls"
	"errors"
	"fmt"
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
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Returning an error (rather than http.ErrUseLastResponse) makes
			// the SDK see a transport failure. ErrUseLastResponse would hand it
			// a 3xx body that it treats as a success and tries to decode.
			return fmt.Errorf("%w to %s", ErrRedirectRejected, req.URL.Scheme+"://"+req.URL.Host)
		},
	}
}
