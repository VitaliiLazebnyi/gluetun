package restrictednet

import (
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newHTTPSClient(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		serverHTTP2 bool
		protoMajor  int
	}{
		"http2_server": {
			serverHTTP2: true,
			protoMajor:  2,
		},
		"http1_server": {
			protoMajor: 1,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewUnstartedServer(http.HandlerFunc(
				func(writer http.ResponseWriter, _ *http.Request) {
					_, _ = writer.Write([]byte("body"))
				}))
			server.EnableHTTP2 = testCase.serverHTTP2
			server.StartTLS()
			t.Cleanup(server.Close)

			dialer := net.Dialer{}
			connection, err := dialer.DialContext(t.Context(), "tcp", server.Listener.Addr().String())
			require.NoError(t, err)
			t.Cleanup(func() { _ = connection.Close() })

			// The httptest server certificate is valid for example.com
			const destinationTLSName = "example.com"
			dial := makeDial(connection, destinationTLSName)
			httpClient := newHTTPSClient(destinationTLSName, dial)

			transport, ok := httpClient.Transport.(*http.Transport)
			require.True(t, ok)
			assert.True(t, transport.ForceAttemptHTTP2)
			rootCAs := x509.NewCertPool()
			rootCAs.AddCert(server.Certificate())
			transport.TLSClientConfig.RootCAs = rootCAs

			_, port, err := net.SplitHostPort(server.Listener.Addr().String())
			require.NoError(t, err)
			url := "https://" + net.JoinHostPort(destinationTLSName, port)

			// Requests are sent sequentially over the single connection dialed,
			// using the transport directly as done by the PureVPN provider.
			const requests = 2
			for range requests {
				request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
				require.NoError(t, err)
				response, err := httpClient.Transport.RoundTrip(request)
				require.NoError(t, err)
				body, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				err = response.Body.Close()
				require.NoError(t, err)

				assert.Equal(t, http.StatusOK, response.StatusCode)
				assert.Equal(t, testCase.protoMajor, response.ProtoMajor)
				assert.Equal(t, "body", string(body))
			}

			httpClient.CloseIdleConnections()
			err = connection.Close()
			assert.ErrorIs(t, err, net.ErrClosed)
		})
	}
}

func Test_makeDial(t *testing.T) {
	t.Parallel()

	listenConfig := net.ListenConfig{}
	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(t.Context(), "tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = connection.Close() })
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	address := net.JoinHostPort("example.com", port)

	dial := makeDial(connection, "example.com")

	dialed, err := dial(t.Context(), "tcp", address)
	require.NoError(t, err)
	assert.Equal(t, connection, dialed)

	dialed, err = dial(t.Context(), "tcp", address)
	assert.ErrorIs(t, err, ErrDialedMoreThanOnce)
	assert.Nil(t, dialed)
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

// Test_newHTTPSClient_dialedMoreThanOnce verifies the error returned by
// the dial function dialing again goes through the HTTP transport, such
// that callers can detect a request was not sent on the connection.
func Test_newHTTPSClient_dialedMoreThanOnce(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		serverHTTP2 bool
		method      string
		body        string
	}{
		"http1_get": {
			method: http.MethodGet,
		},
		"http1_post": {
			method: http.MethodPost,
			body:   "data",
		},
		"http2_get": {
			serverHTTP2: true,
			method:      http.MethodGet,
		},
		"http2_post": {
			serverHTTP2: true,
			method:      http.MethodPost,
			body:        "data",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var requestsCount atomic.Uint32
			server := httptest.NewUnstartedServer(http.HandlerFunc(
				func(writer http.ResponseWriter, _ *http.Request) {
					requestsCount.Add(1)
					_, _ = writer.Write([]byte("body"))
				}))
			server.EnableHTTP2 = testCase.serverHTTP2
			server.StartTLS()
			t.Cleanup(server.Close)

			dialer := net.Dialer{}
			rawConnection, err := dialer.DialContext(t.Context(), "tcp", server.Listener.Addr().String())
			require.NoError(t, err)
			connection := &closeNotifyingConn{Conn: rawConnection, closed: make(chan struct{})}
			t.Cleanup(func() { _ = connection.Close() })

			// The httptest server certificate is valid for example.com
			const destinationTLSName = "example.com"
			dial := makeDial(connection, destinationTLSName)
			httpClient := newHTTPSClient(destinationTLSName, dial)
			transport, ok := httpClient.Transport.(*http.Transport)
			require.True(t, ok)
			rootCAs := x509.NewCertPool()
			rootCAs.AddCert(server.Certificate())
			transport.TLSClientConfig.RootCAs = rootCAs

			_, port, err := net.SplitHostPort(server.Listener.Addr().String())
			require.NoError(t, err)
			url := "https://" + net.JoinHostPort(destinationTLSName, port)

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
			require.NoError(t, err)
			response, err := transport.RoundTrip(request)
			require.NoError(t, err)
			_, err = io.Copy(io.Discard, response.Body)
			require.NoError(t, err)
			err = response.Body.Close()
			require.NoError(t, err)

			// The server closes the connection, and the transport
			// closes its side once it notices it.
			server.CloseClientConnections()
			select {
			case <-connection.closed:
			case <-t.Context().Done():
				t.Fatal(t.Context().Err())
			}

			request, err = http.NewRequestWithContext(t.Context(), testCase.method, url,
				strings.NewReader(testCase.body))
			require.NoError(t, err)
			response, err = transport.RoundTrip(request) //nolint:bodyclose

			assert.ErrorIs(t, err, ErrDialedMoreThanOnce)
			assert.Nil(t, response)
			assert.Equal(t, uint32(1), requestsCount.Load())
		})
	}
}
