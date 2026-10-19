package restrictednet

import (
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
