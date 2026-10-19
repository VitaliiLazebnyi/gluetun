package purevpn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeNetwork is a restricted network dialing a test server once per
// HTTP client opened, and whose HTTP clients can dial only once, like
// the restricted network HTTP clients. It records the hostnames opened,
// the context of the last open and the number of cleanups for each HTTP
// client opened.
type fakeNetwork struct {
	serverAddress string
	rootCAs       *x509.CertPool
	// openErrs maps the index of an open call to the error it returns.
	openErrs map[uint]error
	// cleanupErrs maps the index of an open call to the error
	// wrapped and returned by its cleanup.
	cleanupErrs map[uint]error

	mutex     sync.Mutex
	hostnames []string
	openCtx   context.Context
	cleanups  []uint
}

func newFakeNetwork(server *httptest.Server) *fakeNetwork {
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(server.Certificate())
	return &fakeNetwork{
		serverAddress: server.Listener.Addr().String(),
		rootCAs:       rootCAs,
	}
}

func (n *fakeNetwork) OpenHTTPSByHostname(ctx context.Context, hostname string) (
	*http.Client, func() error, error,
) {
	n.mutex.Lock()
	index := uint(len(n.hostnames))
	n.hostnames = append(n.hostnames, hostname)
	n.openCtx = ctx
	n.cleanups = append(n.cleanups, 0)
	openErr := n.openErrs[index]
	cleanupErr := n.cleanupErrs[index]
	n.mutex.Unlock()
	if openErr != nil {
		return nil, nil, openErr
	}

	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp", n.serverAddress)
	if err != nil {
		return nil, nil, err
	}

	var dialed atomic.Bool
	httpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    n.rootCAs,
			// The httptest server certificate is valid for example.com
			ServerName: "example.com",
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if !dialed.CompareAndSwap(false, true) {
				return nil, errors.New("dial function called more than once")
			}
			return connection, nil
		},
		ForceAttemptHTTP2: true,
	}}
	cleanup := func() error {
		httpClient.CloseIdleConnections()
		_ = connection.Close()
		n.mutex.Lock()
		defer n.mutex.Unlock()
		n.cleanups[index]++
		if cleanupErr != nil {
			return fmt.Errorf("cleanup %d: %w", index, cleanupErr)
		}
		return nil
	}
	return httpClient, cleanup, nil
}

func (n *fakeNetwork) ResolveName(_ context.Context, host string) ([]netip.Addr, error) {
	switch host {
	case "us-ny.purevpn.net":
		return []netip.Addr{netip.MustParseAddr("198.51.100.9")}, nil
	case "empty.purevpn.net":
		return nil, nil
	default:
		return nil, errors.New("unknown host " + host)
	}
}

func (n *fakeNetwork) opened() (hostnames []string, cleanups []uint) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return slices.Clone(n.hostnames), slices.Clone(n.cleanups)
}

// transportTestRequest is a GET request sent through the restricted transport.
type transportTestRequest struct {
	scheme string // defaults to https
	host   string
	// defaultPort omits the port from the request URL.
	defaultPort bool
	// path is the request URL path. The `/redirect` path makes the
	// server redirect to the `/` path on the localhost host.
	path string
	// keepBodyOpen leaves the response body open.
	keepBodyOpen bool
	// opens is the number of restricted connections the request opens.
	opens uint
	// closeErrMessage is the expected response body close error
	// message substring, if any.
	closeErrMessage string
	// errWrapped is the expected sentinel error wrapped, if any.
	errWrapped error
	// errMessage is the expected error message substring,
	// and the request is expected to fail if it is set.
	errMessage string
}

func Test_restrictedTransport(t *testing.T) {
	t.Parallel()

	testErr := errors.New("test error")

	testCases := map[string]struct {
		untrustedServer bool
		openErrs        map[uint]error
		cleanupErrs     map[uint]error
		requests        []transportTestRequest
		// openedHosts are the hosts expected to be opened, with the
		// test server port appended if they have no port.
		openedHosts        []string
		cleanupErrMessages []string
	}{
		"sequential_requests_each_open_a_connection": {
			requests: []transportTestRequest{
				{host: "127.0.0.1", opens: 1},
				{host: "127.0.0.1", opens: 1},
				{host: "localhost", opens: 1},
			},
			openedHosts: []string{"127.0.0.1", "127.0.0.1", "localhost"},
		},
		"redirect_hops_each_open_a_connection": {
			requests: []transportTestRequest{
				{host: "127.0.0.1", path: "/redirect", opens: 2},
			},
			openedHosts: []string{"127.0.0.1", "localhost"},
		},
		"default_https_port": {
			requests: []transportTestRequest{
				{host: "localhost", defaultPort: true, opens: 1},
			},
			openedHosts: []string{"localhost:443"},
		},
		"open_error": {
			openErrs: map[uint]error{0: testErr},
			requests: []transportTestRequest{
				{
					host: "127.0.0.1", opens: 1,
					errWrapped: testErr,
					errMessage: "opening restricted HTTPS connection: test error",
				},
				{host: "127.0.0.1", opens: 1},
			},
			openedHosts: []string{"127.0.0.1", "127.0.0.1"},
		},
		"round_trip_error": {
			untrustedServer: true,
			requests: []transportTestRequest{
				{host: "127.0.0.1", opens: 1, errMessage: "certificate signed by unknown authority"},
			},
			openedHosts: []string{"127.0.0.1"},
		},
		"cleanup_leftovers": {
			requests: []transportTestRequest{
				{host: "127.0.0.1", opens: 1},
				{host: "127.0.0.1", opens: 1, keepBodyOpen: true},
				{host: "localhost", opens: 1, keepBodyOpen: true},
			},
			openedHosts: []string{"127.0.0.1", "127.0.0.1", "localhost"},
		},
		"cleanup_errors_joined": {
			cleanupErrs: map[uint]error{0: testErr, 2: testErr},
			requests: []transportTestRequest{
				{host: "127.0.0.1", opens: 1, closeErrMessage: "cleanup 0: test error"},
				{host: "127.0.0.1", opens: 1},
				{host: "localhost", opens: 1, keepBodyOpen: true},
			},
			openedHosts:        []string{"127.0.0.1", "127.0.0.1", "localhost"},
			cleanupErrMessages: []string{"cleanup 0: test error", "cleanup 2: test error"},
		},
		"non_https_rejected": {
			requests: []transportTestRequest{
				{scheme: "http", host: "127.0.0.1", errMessage: `URL scheme "http" is not https`},
			},
		},
	}

	protocols := map[string]struct {
		serverHTTP2 bool
		protoMajor  int
	}{
		"http1": {protoMajor: 1},
		"http2": {serverHTTP2: true, protoMajor: 2},
	}

	for name, testCase := range testCases {
		for protocolName, protocol := range protocols {
			t.Run(name+"_"+protocolName, func(t *testing.T) {
				t.Parallel()

				var server *httptest.Server
				server = httptest.NewUnstartedServer(http.HandlerFunc(
					func(writer http.ResponseWriter, request *http.Request) {
						if request.URL.Path == "/redirect" {
							_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
							redirectURL := url.URL{Scheme: "https", Host: net.JoinHostPort("localhost", port), Path: "/"}
							http.Redirect(writer, request, redirectURL.String(), http.StatusFound)
							return
						}
						_, _ = writer.Write([]byte(request.URL.Path)) //nolint:gosec
					}))
				server.EnableHTTP2 = protocol.serverHTTP2
				server.StartTLS()
				t.Cleanup(server.Close)
				_, port, err := net.SplitHostPort(server.Listener.Addr().String())
				require.NoError(t, err)

				network := newFakeNetwork(server)
				if testCase.untrustedServer {
					network.rootCAs = x509.NewCertPool()
				}
				network.openErrs = testCase.openErrs
				network.cleanupErrs = testCase.cleanupErrs
				transport := &restrictedTransport{network: network}
				httpClient := &http.Client{Transport: transport}

				for _, testRequest := range testCase.requests {
					checkTransportTestRequest(t, port, network, httpClient, protocol.protoMajor, testRequest)
				}

				expectedHostnames, expectedCleanups := expectedOpened(testCase.openedHosts, port, testCase.openErrs)
				hostnames, _ := network.opened()
				assert.Equal(t, expectedHostnames, hostnames)

				err = transport.cleanup()

				if len(testCase.cleanupErrMessages) == 0 {
					assert.NoError(t, err)
				}
				for _, cleanupErrMessage := range testCase.cleanupErrMessages {
					assert.ErrorIs(t, err, testErr)
					assert.ErrorContains(t, err, cleanupErrMessage)
				}
				_, cleanups := network.opened()
				assert.Equal(t, expectedCleanups, cleanups, "each connection must be cleaned up once")

				// Cleaning up again does nothing.
				err = transport.cleanup()
				assert.NoError(t, err)
				_, cleanups = network.opened()
				assert.Equal(t, expectedCleanups, cleanups)
			})
		}
	}
}

// expectedOpened returns the hostnames expected to be opened, appending
// the port to the hosts without port, and the number of cleanups expected
// for each of them, 0 if opening it fails and 1 otherwise.
func expectedOpened(hosts []string, port string, openErrs map[uint]error) (
	hostnames []string, cleanups []uint,
) {
	for i, host := range hosts {
		hostname := host
		_, _, err := net.SplitHostPort(host)
		if err != nil {
			hostname = net.JoinHostPort(host, port)
		}
		hostnames = append(hostnames, hostname)
		cleanup := uint(1)
		if openErrs[uint(i)] != nil {
			cleanup = 0
		}
		cleanups = append(cleanups, cleanup)
	}
	return hostnames, cleanups
}

// checkTransportTestRequest sends the test GET request and checks its outcome,
// and that the connections it opened are cleaned up only once done with.
func checkTransportTestRequest(t *testing.T, serverPort string, network *fakeNetwork,
	httpClient *http.Client, protoMajor int, testRequest transportTestRequest,
) {
	t.Helper()

	scheme := "https"
	if testRequest.scheme != "" {
		scheme = testRequest.scheme
	}
	host := testRequest.host
	if !testRequest.defaultPort {
		host = net.JoinHostPort(testRequest.host, serverPort)
	}
	requestURL := url.URL{Scheme: scheme, Host: host, Path: testRequest.path}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, requestURL.String(), nil)
	require.NoError(t, err)

	_, cleanupsBefore := network.opened()

	response, err := httpClient.Do(request)

	_, cleanups := network.opened()
	newCleanups := cleanups[len(cleanupsBefore):]
	require.Len(t, newCleanups, int(testRequest.opens))
	if testRequest.errMessage != "" {
		if testRequest.errWrapped != nil {
			assert.ErrorIs(t, err, testRequest.errWrapped)
		}
		assert.ErrorContains(t, err, testRequest.errMessage)
		for i, cleanup := range newCleanups {
			openIndex := uint(len(cleanupsBefore) + i)
			if network.openErrs[openIndex] != nil {
				assert.Zero(t, cleanup, "a connection failing to open must not be cleaned up")
				continue
			}
			assert.Equal(t, uint(1), cleanup, "a failed request connection must be cleaned up")
		}
		return
	}
	require.NoError(t, err)
	last := len(newCleanups) - 1
	for _, cleanup := range newCleanups[:last] {
		assert.Equal(t, uint(1), cleanup, "a redirect response connection must be cleaned up")
	}
	assert.Zero(t, newCleanups[last], "the connection must not be cleaned up before the body is closed")

	responseBody, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	assert.Equal(t, protoMajor, response.ProtoMajor)
	expectedBody := testRequest.path
	if expectedBody == "" || expectedBody == "/redirect" {
		expectedBody = "/"
	}
	assert.Equal(t, expectedBody, string(responseBody))

	if testRequest.keepBodyOpen {
		return
	}
	err = response.Body.Close()
	if testRequest.closeErrMessage == "" {
		assert.NoError(t, err)
	} else {
		assert.ErrorContains(t, err, testRequest.closeErrMessage)
	}
	_, cleanups = network.opened()
	assert.Equal(t, uint(1), cleanups[len(cleanupsBefore)+last],
		"the connection must be cleaned up once the body is closed")
}
