package purevpn

import (
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/qdm12/gluetun/internal/restrictednet"
)

// restrictedTransport is an [http.RoundTripper] reaching HTTPS hosts before
// the VPN is up, through the restricted network temporary firewall rules.
// It keeps one restricted connection and its firewall rule per host, such that
// sequential requests to the same host share the same connection, and requests
// can go to different hosts, for example when following redirects between the
// PureVPN websites. The connections are kept open, and their firewall rules
// kept in place, until [restrictedTransport.cleanup] is called.
//
// It must be used by one goroutine only, sending requests sequentially:
// a restricted network HTTP client dials only once, so each response body
// must also be fully read and closed before the next request is sent.
// The wgapi client always reads and closes the response bodies, and the
// [http.Client] closes redirect response bodies before following redirects.
type restrictedTransport struct {
	network RestrictedNetwork
	clients map[string]restrictedClient
	// cleanupErrs are the errors encountered cleaning up clients
	// replaced during round trips.
	cleanupErrs []error
}

type restrictedClient struct {
	httpClient *http.Client
	cleanup    func() error
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

	client, ok := t.clients[hostname]
	if !ok {
		var err error
		client, err = t.open(request, hostname)
		if err != nil {
			return nil, err
		}
	}

	response, err := roundTrip(client, request)
	if err == nil {
		return response, nil
	}
	// The single connection of the client is unusable after an error.
	t.discard(hostname)
	if !errors.Is(err, restrictednet.ErrDialedMoreThanOnce) {
		// The request may have been processed by the server, so it must
		// not be sent again, for example to not submit a one time
		// password twice.
		return nil, err
	}

	// The connection was already unusable when the request was about to be
	// sent, for example since the server closed it after an idle timeout or
	// with a `Connection: close` response header, and the HTTP transport
	// dialed again, which the restricted network HTTP client refuses.
	// The HTTP transport only dials again before sending the request, or to
	// retry a request it considers safe to retry, so retry once on a new
	// connection.
	retryRequest, ok, rewindErr := rewind(request)
	switch {
	case rewindErr != nil:
		return nil, errors.Join(err, rewindErr)
	case !ok:
		return nil, err
	}
	client, err = t.open(retryRequest, hostname)
	if err != nil {
		return nil, err
	}
	response, err = roundTrip(client, retryRequest)
	if err != nil {
		t.discard(hostname)
		return nil, err
	}
	return response, nil
}

// roundTrip uses the transport directly so the request context and the
// timeout of the client using the restricted transport apply, instead of
// the timeout of the restricted network HTTP client.
func roundTrip(client restrictedClient, request *http.Request) (*http.Response, error) {
	return client.httpClient.Transport.RoundTrip(request)
}

// open opens a restricted HTTPS connection to the hostname and stores
// its client for the hostname.
func (t *restrictedTransport) open(request *http.Request, hostname string) (
	client restrictedClient, err error,
) {
	httpClient, cleanup, err := t.network.OpenHTTPSByHostname(request.Context(), hostname)
	if err != nil {
		return restrictedClient{}, fmt.Errorf("opening restricted HTTPS connection: %w", err)
	}
	client = restrictedClient{httpClient: httpClient, cleanup: cleanup}
	if t.clients == nil {
		t.clients = make(map[string]restrictedClient)
	}
	t.clients[hostname] = client
	return client, nil
}

// discard cleans up the client for the hostname and removes it.
func (t *restrictedTransport) discard(hostname string) {
	err := t.clients[hostname].cleanup()
	if err != nil {
		t.cleanupErrs = append(t.cleanupErrs, err)
	}
	delete(t.clients, hostname)
}

// rewind returns a request to send again, and false if the request
// cannot be sent again since its body cannot be read again. The body
// of the request given is consumed or closed by the HTTP transport,
// even if the request was not sent.
func rewind(request *http.Request) (rewound *http.Request, ok bool, err error) {
	switch {
	case request.Body == nil || request.Body == http.NoBody:
		return request, true, nil
	case request.GetBody == nil:
		return nil, false, nil
	}
	body, err := request.GetBody()
	if err != nil {
		return nil, false, fmt.Errorf("getting request body: %w", err)
	}
	rewound = request.Clone(request.Context())
	rewound.Body = body
	return rewound, true, nil
}

// cleanup closes all the connections opened and removes their firewall rules,
// returning all the errors encountered, including the ones encountered
// cleaning up connections replaced during the round trips.
func (t *restrictedTransport) cleanup() error {
	errs := t.cleanupErrs
	for _, client := range t.clients {
		errs = append(errs, client.cleanup())
	}
	t.clients = nil
	t.cleanupErrs = nil
	return errors.Join(errs...)
}
