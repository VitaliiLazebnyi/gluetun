package purevpn

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
)

// restrictedTransport is an [http.RoundTripper] reaching HTTPS hosts before
// the VPN is up, through the restricted network temporary firewall rules.
// It keeps one restricted connection and its firewall rule per host, such that
// sequential requests to the same host share the same connection, and requests
// can go to different hosts, for example when following redirects between the
// PureVPN websites. The connections are kept open, and their firewall rules
// kept in place, until [restrictedTransport.cleanup] is called.
//
// Since a restricted network HTTP client dials only once, requests must be sent
// sequentially and each response body must be fully read and closed before the
// next request is sent. The wgapi client always reads and closes the response
// bodies, and the [http.Client] closes redirect response bodies before following
// redirects.
type restrictedTransport struct {
	network RestrictedNetwork
	// mutex is held during each round trip, to send requests sequentially.
	mutex   sync.Mutex
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

	t.mutex.Lock()
	defer t.mutex.Unlock()

	client, reused := t.clients[hostname]
	if !reused {
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
	if !reused || request.Context().Err() != nil {
		return nil, err
	}

	// The server likely closed the connection of the client reused,
	// for example after an idle timeout or with a `Connection: close`
	// response header, so retry once with a new connection if possible.
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
// its client for the hostname. It must be called with the mutex locked.
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
// It must be called with the mutex locked.
func (t *restrictedTransport) discard(hostname string) {
	err := t.clients[hostname].cleanup()
	if err != nil {
		t.cleanupErrs = append(t.cleanupErrs, err)
	}
	delete(t.clients, hostname)
}

// rewind returns a request to send again, and false if the request
// cannot be sent again since its body cannot be read again.
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
	t.mutex.Lock()
	defer t.mutex.Unlock()
	errs := t.cleanupErrs
	for _, client := range t.clients {
		errs = append(errs, client.cleanup())
	}
	t.clients = nil
	t.cleanupErrs = nil
	return errors.Join(errs...)
}
