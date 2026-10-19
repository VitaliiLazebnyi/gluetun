package purevpn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// singleConnectionNetwork is a restricted network dialing a test server
// once per HTTP client opened, like the restricted network HTTP clients,
// and recording the error closing the connection on cleanup.
type singleConnectionNetwork struct {
	serverAddress string
	rootCAs       *x509.CertPool
	cleanups      uint
	closeErr      error
}

func (n *singleConnectionNetwork) OpenHTTPSByHostname(ctx context.Context, _ string) (
	*http.Client, func() error, error,
) {
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp", n.serverAddress)
	if err != nil {
		return nil, nil, err
	}
	dialed := false
	httpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    n.rootCAs,
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if dialed {
				return nil, errors.New("dial function called more than once")
			}
			dialed = true
			return connection, nil
		},
		ForceAttemptHTTP2: true,
	}}
	cleanup := func() error {
		n.cleanups++
		httpClient.CloseIdleConnections()
		n.closeErr = connection.Close()
		return nil
	}
	return httpClient, cleanup, nil
}

func (n *singleConnectionNetwork) ResolveName(context.Context, string) ([]netip.Addr, error) {
	panic("not implemented")
}

func Test_restrictedTransport(t *testing.T) {
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

			rootCAs := x509.NewCertPool()
			rootCAs.AddCert(server.Certificate())
			network := &singleConnectionNetwork{
				serverAddress: server.Listener.Addr().String(),
				rootCAs:       rootCAs,
			}
			transport := &restrictedTransport{network: network}
			httpClient := &http.Client{Transport: transport}

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
			require.NoError(t, err)
			response, err := httpClient.Do(request)
			require.NoError(t, err)
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			assert.Equal(t, testCase.protoMajor, response.ProtoMajor)
			assert.Equal(t, "body", string(body))
			assert.Zero(t, network.cleanups)

			err = response.Body.Close()
			require.NoError(t, err)
			assert.Equal(t, uint(1), network.cleanups)
			// The connection is no longer in use once the body is closed,
			// so closing idle connections already closed it.
			assert.ErrorIs(t, network.closeErr, net.ErrClosed)

			err = transport.cleanup()
			assert.NoError(t, err)
			assert.Equal(t, uint(1), network.cleanups)
		})
	}
}
