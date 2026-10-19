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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// singleConnectionNetwork is a restricted network dialing a test server
// once per HTTP client opened, and whose HTTP clients can dial only once,
// like the restricted network HTTP clients. It records the hostnames
// opened and the number of cleanups for each HTTP client opened.
type singleConnectionNetwork struct {
	serverAddress string
	rootCAs       *x509.CertPool
	// cleanupErr, if set, is wrapped and returned by each cleanup.
	cleanupErr error

	mutex     sync.Mutex
	hostnames []string
	cleanups  []uint
}

func (n *singleConnectionNetwork) OpenHTTPSByHostname(ctx context.Context, hostname string) (
	*http.Client, func() error, error,
) {
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp", n.serverAddress)
	if err != nil {
		return nil, nil, err
	}

	n.mutex.Lock()
	index := len(n.hostnames)
	n.hostnames = append(n.hostnames, hostname)
	n.cleanups = append(n.cleanups, 0)
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
		if n.cleanupErr != nil {
			return fmt.Errorf("cleanup %d: %w", index, n.cleanupErr)
		}
		return nil
	}
	return httpClient, cleanup, nil
}

func (n *singleConnectionNetwork) ResolveName(context.Context, string) ([]netip.Addr, error) {
	panic("not implemented")
}

func (n *singleConnectionNetwork) opened() (hostnames []string, cleanups []uint) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return slices.Clone(n.hostnames), slices.Clone(n.cleanups)
}

// transportTestRequest is a request sent through the restricted transport.
type transportTestRequest struct {
	scheme string // defaults to https
	host   string
	body   *string
	// notReplayable makes the request body impossible to read again.
	notReplayable bool
	// closeConnectionsBefore closes the server side of the connections
	// before sending the request.
	closeConnectionsBefore bool
	// fails is true if the request is expected to fail.
	fails bool
	// errMessage is the expected error message substring, if any.
	errMessage string
}

func Test_restrictedTransport(t *testing.T) {
	t.Parallel()

	testErr := errors.New("test error")

	testCases := map[string]struct {
		untrustedServer bool
		cleanupErr      error
		requests        []transportTestRequest
		openedHosts     []string
		cleanupErrs     []string
	}{
		"same_host_reuses_connection": {
			requests: []transportTestRequest{
				{host: "127.0.0.1"},
				{host: "127.0.0.1", body: new("data")},
				{host: "127.0.0.1"},
			},
			openedHosts: []string{"127.0.0.1"},
		},
		"different_hosts_use_different_connections": {
			requests: []transportTestRequest{
				{host: "127.0.0.1"},
				{host: "localhost"},
				{host: "127.0.0.1"},
				{host: "localhost"},
			},
			openedHosts: []string{"127.0.0.1", "localhost"},
		},
		"server_closed_connection_reopened": {
			requests: []transportTestRequest{
				{host: "127.0.0.1"},
				{host: "127.0.0.1", closeConnectionsBefore: true},
				{host: "127.0.0.1"},
			},
			openedHosts: []string{"127.0.0.1", "127.0.0.1"},
		},
		"server_closed_connection_reopened_with_body": {
			requests: []transportTestRequest{
				{host: "127.0.0.1"},
				{host: "127.0.0.1", body: new("data"), closeConnectionsBefore: true},
			},
			openedHosts: []string{"127.0.0.1", "127.0.0.1"},
		},
		"server_closed_connection_body_not_replayable": {
			requests: []transportTestRequest{
				{host: "127.0.0.1"},
				{
					host: "127.0.0.1", body: new("data"), notReplayable: true,
					closeConnectionsBefore: true, fails: true,
				},
				// The failed connection is replaced on the next request.
				{host: "127.0.0.1"},
			},
			openedHosts: []string{"127.0.0.1", "127.0.0.1"},
		},
		"fresh_connection_error_not_retried": {
			untrustedServer: true,
			requests: []transportTestRequest{
				{host: "127.0.0.1", fails: true, errMessage: "certificate signed by unknown authority"},
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
			openedHosts: []string{"127.0.0.1", "localhost", "127.0.0.1"},
			cleanupErrs: []string{"cleanup 0: test error", "cleanup 1: test error", "cleanup 2: test error"},
		},
		"non_https_rejected": {
			requests: []transportTestRequest{
				{scheme: "http", host: "127.0.0.1", fails: true, errMessage: `URL scheme "http" is not https`},
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

				server := httptest.NewUnstartedServer(http.HandlerFunc(
					func(writer http.ResponseWriter, request *http.Request) {
						body, _ := io.ReadAll(request.Body)
						_, _ = writer.Write([]byte(request.Method + " " + string(body))) //nolint:gosec
					}))
				server.EnableHTTP2 = protocol.serverHTTP2
				server.StartTLS()
				t.Cleanup(server.Close)
				_, port, err := net.SplitHostPort(server.Listener.Addr().String())
				require.NoError(t, err)

				rootCAs := x509.NewCertPool()
				if !testCase.untrustedServer {
					rootCAs.AddCert(server.Certificate())
				}
				network := &singleConnectionNetwork{
					serverAddress: server.Listener.Addr().String(),
					rootCAs:       rootCAs,
					cleanupErr:    testCase.cleanupErr,
				}
				transport := &restrictedTransport{network: network}
				httpClient := &http.Client{Transport: transport}

				for _, testRequest := range testCase.requests {
					checkTransportTestRequest(t, server, httpClient, protocol.protoMajor, testRequest)
				}

				var expectedHostnames []string
				var expectedCleanups []uint
				for _, host := range testCase.openedHosts {
					expectedHostnames = append(expectedHostnames, net.JoinHostPort(host, port))
					expectedCleanups = append(expectedCleanups, 1)
				}
				hostnames, _ := network.opened()
				assert.Equal(t, expectedHostnames, hostnames)

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

// checkTransportTestRequest sends the test request, a GET request if
// it has no body, or a POST request with its body otherwise, and checks
// the outcome.
func checkTransportTestRequest(t *testing.T, server *httptest.Server, httpClient *http.Client,
	protoMajor int, testRequest transportTestRequest,
) {
	t.Helper()

	if testRequest.closeConnectionsBefore {
		server.CloseClientConnections()
	}
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	require.NoError(t, err)
	scheme := "https"
	if testRequest.scheme != "" {
		scheme = testRequest.scheme
	}
	requestURL := url.URL{Scheme: scheme, Host: net.JoinHostPort(testRequest.host, port)}

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

	response, err := httpClient.Do(request)

	if testRequest.fails {
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
