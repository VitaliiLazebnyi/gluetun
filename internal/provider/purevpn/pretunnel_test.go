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
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/qdm12/gluetun/internal/restrictednet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeNetwork is a restricted network dialing a test server once per
// HTTP client opened, and whose HTTP clients can dial only once, failing
// with [restrictednet.ErrDialedMoreThanOnce] otherwise, like the restricted
// network HTTP clients. It records the hostnames opened, the context of the
// last open and the number of cleanups for each HTTP client opened.
type fakeNetwork struct {
	serverAddress string
	rootCAs       *x509.CertPool
	// openErrs maps the index of an open call to the error it returns.
	openErrs map[uint]error
	// cleanupErr, if set, is wrapped and returned by each cleanup.
	cleanupErr error

	mutex       sync.Mutex
	hostnames   []string
	openCtx     context.Context
	cleanups    []uint
	connections []*closeNotifyingConn
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
	n.mutex.Unlock()
	if openErr != nil {
		return nil, nil, openErr
	}

	dialer := net.Dialer{}
	rawConnection, err := dialer.DialContext(ctx, "tcp", n.serverAddress)
	if err != nil {
		return nil, nil, err
	}
	connection := &closeNotifyingConn{Conn: rawConnection, closed: make(chan struct{})}
	n.mutex.Lock()
	n.connections = append(n.connections, connection)
	n.mutex.Unlock()

	var dialed atomic.Bool
	httpClient := &http.Client{Transport: &http.Transport{
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		MaxConnsPerHost:     1,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    n.rootCAs,
			// The httptest server certificate is valid for example.com
			ServerName: "example.com",
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if !dialed.CompareAndSwap(false, true) {
				return nil, restrictednet.ErrDialedMoreThanOnce
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
		if n.cleanupErr != nil {
			return fmt.Errorf("cleanup %d: %w", index, n.cleanupErr)
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

// waitClosed waits for all the connections opened to be closed,
// for example by the HTTP transport after the server closed them.
func (n *fakeNetwork) waitClosed(t *testing.T) {
	t.Helper()
	n.mutex.Lock()
	connections := slices.Clone(n.connections)
	n.mutex.Unlock()
	for _, connection := range connections {
		select {
		case <-connection.closed:
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
	}
}

// closeNotifyingConn is a connection closing its closed channel
// the first time it is closed.
type closeNotifyingConn struct {
	net.Conn
	closeOnce sync.Once
	closed    chan struct{}
}

func (c *closeNotifyingConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// transportTestRequest is a request sent through the restricted transport.
type transportTestRequest struct {
	scheme string // defaults to https
	host   string
	// defaultPort omits the port from the request URL.
	defaultPort bool
	// path is the request URL path. The `/drop` path makes the server
	// close all the client connections after reading the request,
	// without responding.
	path string
	body *string
	// notReplayable makes the request body impossible to read again.
	notReplayable bool
	// getBodyErr, if set, is returned by the request GetBody function.
	getBodyErr error
	// closeConnectionsBefore closes the server side of the connections
	// before sending the request, and waits for the client side of the
	// connections to be closed.
	closeConnectionsBefore bool
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
		cleanupErr      error
		requests        []transportTestRequest
		// openedHosts are the hosts expected to be opened, with the
		// test server port appended if they have no port.
		openedHosts    []string
		serverRequests uint32
		cleanupErrs    []string
	}{
		"same_host_reuses_connection": {
			requests: []transportTestRequest{
				{host: "127.0.0.1"},
				{host: "127.0.0.1", body: new("data")},
				{host: "127.0.0.1"},
			},
			openedHosts:    []string{"127.0.0.1"},
			serverRequests: 3,
		},
		"default_https_port": {
			requests: []transportTestRequest{
				{host: "localhost", defaultPort: true},
			},
			openedHosts:    []string{"localhost:443"},
			serverRequests: 1,
		},
		"different_hosts_use_different_connections": {
			requests: []transportTestRequest{
				{host: "127.0.0.1"},
				{host: "localhost"},
				{host: "127.0.0.1"},
				{host: "localhost"},
			},
			openedHosts:    []string{"127.0.0.1", "localhost"},
			serverRequests: 4,
		},
		"server_closed_connection_reopened": {
			requests: []transportTestRequest{
				{host: "127.0.0.1"},
				{host: "127.0.0.1", closeConnectionsBefore: true},
				{host: "127.0.0.1"},
			},
			openedHosts:    []string{"127.0.0.1", "127.0.0.1"},
			serverRequests: 3,
		},
		"server_closed_connection_reopened_with_body": {
			requests: []transportTestRequest{
				{host: "127.0.0.1"},
				{host: "127.0.0.1", body: new("data"), closeConnectionsBefore: true},
			},
			openedHosts:    []string{"127.0.0.1", "127.0.0.1"},
			serverRequests: 2,
		},
		"server_closed_connection_body_not_replayable": {
			requests: []transportTestRequest{
				{host: "127.0.0.1"},
				{
					host: "127.0.0.1", body: new("data"), notReplayable: true,
					closeConnectionsBefore: true,
					errWrapped:             restrictednet.ErrDialedMoreThanOnce,
					errMessage:             "dial function called more than once",
				},
				// The failed connection is replaced on the next request.
				{host: "127.0.0.1"},
			},
			openedHosts:    []string{"127.0.0.1", "127.0.0.1"},
			serverRequests: 2,
		},
		"server_closed_connection_get_body_error": {
			requests: []transportTestRequest{
				{host: "127.0.0.1"},
				{
					host: "127.0.0.1", body: new("data"), getBodyErr: testErr,
					closeConnectionsBefore: true,
					errWrapped:             testErr,
					errMessage: "dial function called more than once\n" +
						"getting request body: test error",
				},
			},
			openedHosts:    []string{"127.0.0.1"},
			serverRequests: 1,
		},
		"server_closed_connection_reopen_error": {
			openErrs: map[uint]error{1: testErr},
			requests: []transportTestRequest{
				{host: "127.0.0.1"},
				{
					host: "127.0.0.1", closeConnectionsBefore: true,
					errWrapped: testErr,
					errMessage: "opening restricted HTTPS connection: test error",
				},
			},
			openedHosts:    []string{"127.0.0.1", "127.0.0.1"},
			serverRequests: 1,
		},
		"server_closed_connection_retried_request_error": {
			requests: []transportTestRequest{
				{host: "127.0.0.1"},
				{
					host: "127.0.0.1", path: "/drop", closeConnectionsBefore: true,
					errMessage: "EOF",
				},
				// The failed connection is replaced on the next request.
				{host: "127.0.0.1"},
			},
			openedHosts:    []string{"127.0.0.1", "127.0.0.1", "127.0.0.1"},
			serverRequests: 3,
		},
		"request_processed_then_connection_closed_not_replayed": {
			requests: []transportTestRequest{
				{host: "127.0.0.1"},
				{
					host: "127.0.0.1", path: "/drop", body: new("data"),
					errMessage: "EOF",
				},
				// The failed connection is replaced on the next request.
				{host: "127.0.0.1"},
			},
			openedHosts:    []string{"127.0.0.1", "127.0.0.1"},
			serverRequests: 3,
		},
		"fresh_connection_error_not_retried": {
			untrustedServer: true,
			requests: []transportTestRequest{
				{host: "127.0.0.1", errMessage: "certificate signed by unknown authority"},
			},
			openedHosts: []string{"127.0.0.1"},
		},
		"cleanup_errors_joined": {
			cleanupErr: testErr,
			requests: []transportTestRequest{
				{host: "127.0.0.1"},
				{host: "localhost"},
				{host: "127.0.0.1", closeConnectionsBefore: true},
			},
			openedHosts:    []string{"127.0.0.1", "localhost", "127.0.0.1"},
			serverRequests: 3,
			cleanupErrs:    []string{"cleanup 0: test error", "cleanup 1: test error", "cleanup 2: test error"},
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

				var serverRequests atomic.Uint32
				var server *httptest.Server
				server = httptest.NewUnstartedServer(http.HandlerFunc(
					func(writer http.ResponseWriter, request *http.Request) {
						serverRequests.Add(1)
						body, _ := io.ReadAll(request.Body)
						if request.URL.Path == "/drop" {
							server.CloseClientConnections()
							return
						}
						_, _ = writer.Write([]byte(request.Method + " " + string(body))) //nolint:gosec
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
				network.cleanupErr = testCase.cleanupErr
				transport := &restrictedTransport{network: network}
				httpClient := &http.Client{Transport: transport}

				for _, testRequest := range testCase.requests {
					checkTransportTestRequest(t, server, network, httpClient, protocol.protoMajor, testRequest)
				}

				expectedHostnames, expectedCleanups := expectedOpened(testCase.openedHosts, port, testCase.openErrs)
				hostnames, _ := network.opened()
				assert.Equal(t, expectedHostnames, hostnames)
				assert.Equal(t, testCase.serverRequests, serverRequests.Load())

				err = transport.cleanup()

				if len(testCase.cleanupErrs) == 0 {
					assert.NoError(t, err)
				}
				for _, cleanupErr := range testCase.cleanupErrs {
					assert.ErrorIs(t, err, testCase.cleanupErr)
					assert.ErrorContains(t, err, cleanupErr)
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

// checkTransportTestRequest sends the test request, a GET request if
// it has no body, or a POST request with its body otherwise, and checks
// the outcome.
func checkTransportTestRequest(t *testing.T, server *httptest.Server, network *fakeNetwork,
	httpClient *http.Client, protoMajor int, testRequest transportTestRequest,
) {
	t.Helper()

	if testRequest.closeConnectionsBefore {
		server.CloseClientConnections()
		network.waitClosed(t)
	}
	scheme := "https"
	if testRequest.scheme != "" {
		scheme = testRequest.scheme
	}
	host := testRequest.host
	if !testRequest.defaultPort {
		_, port, err := net.SplitHostPort(server.Listener.Addr().String())
		require.NoError(t, err)
		host = net.JoinHostPort(testRequest.host, port)
	}
	requestURL := url.URL{Scheme: scheme, Host: host, Path: testRequest.path}

	method := http.MethodGet
	var body io.Reader
	expectedBody := "GET "
	if testRequest.body != nil {
		method = http.MethodPost
		body = strings.NewReader(*testRequest.body)
		if testRequest.notReplayable {
			// The request GetBody field is only set for known body types.
			body = io.NopCloser(body)
		}
		expectedBody = "POST " + *testRequest.body
	}
	request, err := http.NewRequestWithContext(t.Context(), method, requestURL.String(), body)
	require.NoError(t, err)
	if testRequest.getBodyErr != nil {
		request.GetBody = func() (io.ReadCloser, error) {
			return nil, testRequest.getBodyErr
		}
	}

	response, err := httpClient.Do(request)

	if testRequest.errMessage != "" {
		if testRequest.errWrapped != nil {
			assert.ErrorIs(t, err, testRequest.errWrapped)
		}
		assert.ErrorContains(t, err, testRequest.errMessage)
		return
	}
	require.NoError(t, err)
	responseBody, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	err = response.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, protoMajor, response.ProtoMajor)
	assert.Equal(t, expectedBody, string(responseBody))
}
