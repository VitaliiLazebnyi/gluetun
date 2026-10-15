package purevpn

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
)

// restrictedTransport is an [http.RoundTripper] reaching HTTPS hosts before
// the VPN is up, through the restricted network temporary firewall rules.
// Each request uses its own connection and firewall rule, since a restricted
// network HTTP client dials only once, and requests can go to different hosts,
// for example when following redirects between the PureVPN websites.
type restrictedTransport struct {
	network  RestrictedNetwork
	mutex    sync.Mutex
	cleanups []func() error
}

func (t *restrictedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" {
		return nil, fmt.Errorf("URL scheme %q is not https", request.URL.Scheme)
	}
	port := request.URL.Port()
	if port == "" {
		port = "443"
	}
	hostname := net.JoinHostPort(request.URL.Hostname(), port)
	httpClient, cleanup, err := t.network.OpenHTTPSByHostname(request.Context(), hostname)
	if err != nil {
		return nil, fmt.Errorf("opening restricted HTTPS connection: %w", err)
	}
	cleanupOnce := sync.OnceValue(cleanup)
	t.mutex.Lock()
	t.cleanups = append(t.cleanups, cleanupOnce)
	t.mutex.Unlock()

	// Use the transport directly so the request context and the timeout
	// of the client using this transport apply, instead of the timeout
	// of the restricted network HTTP client.
	response, err := httpClient.Transport.RoundTrip(request)
	if err != nil {
		_ = cleanupOnce()
		return nil, err
	}
	response.Body = &cleanupBody{ReadCloser: response.Body, cleanup: cleanupOnce}
	return response, nil
}

// cleanup closes all the connections opened and removes their firewall rules,
// returning all the errors encountered, including ones already returned when
// closing response bodies.
func (t *restrictedTransport) cleanup() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	errs := make([]error, 0, len(t.cleanups))
	for _, cleanup := range t.cleanups {
		errs = append(errs, cleanup())
	}
	t.cleanups = nil
	return errors.Join(errs...)
}

// cleanupBody closes the connection and removes its firewall rule
// once the response body is closed.
type cleanupBody struct {
	io.ReadCloser
	cleanup func() error
}

func (b *cleanupBody) Close() error {
	return errors.Join(b.ReadCloser.Close(), b.cleanup())
}
