package purevpn

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// newTestDoHServer returns a DNS over HTTPS server answering
// 127.0.0.1 for A queries of the hosts given, and NXDOMAIN otherwise.
func newTestDoHServer(t *testing.T, hosts ...string) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || r.Method != http.MethodPost ||
			r.Header.Get("Content-Type") != "application/dns-message" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		query := new(dns.Msg)
		err = query.Unpack(body)
		if err != nil || len(query.Question) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		answer := new(dns.Msg)
		answer.SetReply(query)
		answer.Rcode = dns.RcodeNameError
		for _, host := range hosts {
			if query.Question[0].Name == dns.Fqdn(host) && query.Question[0].Qtype == dns.TypeA {
				answer.Rcode = dns.RcodeSuccess
				answer.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: dns.Fqdn(host), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.IPv4(127, 0, 0, 1),
				}}
			}
		}
		packed, err := answer.Pack()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(packed)
	}))
	t.Cleanup(server.Close)
	return server
}

func serverPort(t *testing.T, server *httptest.Server) uint16 {
	t.Helper()
	parsedURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	port, err := strconv.ParseUint(parsedURL.Port(), 10, 16)
	require.NoError(t, err)
	return uint16(port)
}

// markRecorder records dial control calls instead of setting a socket
// mark, which requires the CAP_NET_ADMIN capability.
type markRecorder struct {
	mutex     sync.Mutex
	addresses []string
}

func (m *markRecorder) control(_, address string, _ syscall.RawConn) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.addresses = append(m.addresses, address)
	return nil
}

func (m *markRecorder) dialed() []string {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return append([]string(nil), m.addresses...)
}

func Test_newPreTunnelHTTPClient(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	testDoHServer := newTestDoHServer(t, "auth.example.com")
	dohPort := serverPort(t, testDoHServer)
	purevpnServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("purevpn"))
	}))
	t.Cleanup(purevpnServer.Close)
	purevpnPort := serverPort(t, purevpnServer)

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(testDoHServer.Certificate())
	rootCAs.AddCert(purevpnServer.Certificate())
	marks := &markRecorder{}
	preTunnel := preTunnelSettings{
		dohServers: []dohServer{
			{
				url: "https://doh.example.com:" + fmt.Sprint(dohPort) + "/dns-query",
				ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
			},
		},
		hosts:       []string{"auth.example.com"},
		port:        purevpnPort,
		mark:        0x7075,
		dialControl: marks.control,
		rootCAs:     rootCAs,
	}
	var reverts []string
	revertDoH := func(context.Context) error {
		reverts = append(reverts, "DoH")
		return nil
	}
	revertPureVPN := func(context.Context) error {
		reverts = append(reverts, "PureVPN")
		return errors.New("test revert error")
	}
	ctx := context.Background()
	firewall := NewMockFirewall(ctrl)
	gomock.InOrder(
		firewall.EXPECT().AllowOutputTemporarily(ctx, "tcp", uint32(0x7075),
			[]netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), dohPort)}).
			Return(revertDoH, nil),
		firewall.EXPECT().AllowOutputTemporarily(ctx, "tcp", uint32(0x7075),
			[]netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), purevpnPort)}).
			Return(revertPureVPN, nil),
	)
	logger := NewMockLogger(ctrl)

	client, resolve, cleanup, err := newPreTunnelHTTPClient(ctx, firewall, logger, preTunnel)
	require.NoError(t, err)

	assert.Equal(t, 30*time.Second, client.Timeout)
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Equal(t, 10*time.Second, transport.TLSHandshakeTimeout)
	assert.Nil(t, transport.Proxy, "proxy must never be used")
	assert.Empty(t, reverts)
	assert.Equal(t, []string{fmt.Sprintf("127.0.0.1:%d", dohPort)}, marks.dialed(),
		"DNS over HTTPS connection must be marked")

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		fmt.Sprintf("https://auth.example.com:%d/", purevpnPort), nil)
	require.NoError(t, err)
	response, err := client.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	assert.Equal(t, "purevpn", string(body))
	assert.Equal(t, []string{
		fmt.Sprintf("127.0.0.1:%d", dohPort),
		fmt.Sprintf("127.0.0.1:%d", purevpnPort),
	}, marks.dialed(), "PureVPN connection must be marked")

	refusedURLs := map[string]string{
		"other_host": fmt.Sprintf("https://other.example.com:%d/", purevpnPort),
		"other_port": fmt.Sprintf("https://auth.example.com:%d/", dohPort),
	}
	for name, refusedURL := range refusedURLs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, refusedURL, nil)
			require.NoError(t, err)
			response, err := client.Do(request)
			if err == nil {
				_ = response.Body.Close()
			}
			assert.ErrorContains(t, err, "is not allowed before the VPN is up")
		})
	}

	ips, err := resolve(context.Background(), "auth.example.com")
	require.NoError(t, err)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("127.0.0.1")}, ips)

	t.Cleanup(func() {
		logger.EXPECT().Warn("removing temporary firewall rules: test revert error")
		failedReverts := cleanup()
		assert.Equal(t, []string{"PureVPN", "DoH"}, reverts, "reverts must be done in reverse order")
		require.Len(t, failedReverts, 1)
		err := failedReverts[0](context.Background())
		assert.EqualError(t, err, "test revert error")
		assert.Equal(t, []string{"PureVPN", "DoH", "PureVPN"}, reverts, "failed revert must be returned")
	})
}

func Test_newPreTunnelHTTPClient_errors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		dohURL string // defaults to the test DNS over HTTPS server URL
		host   string
		// allowErrs are the errors returned by each AllowOutputTemporarily call expected.
		allowErrs  []error
		revertErr  error
		warning    string
		reverts    []string
		errMessage string
	}{
		"invalid_DoH_URL": {
			dohURL:     "https://doh.example.com:99999/dns-query",
			host:       "auth.example.com",
			errMessage: "parsing DNS over HTTPS URL: parsing port: ",
		},
		"allow_DoH_error": {
			allowErrs:  []error{errors.New("test error")},
			host:       "auth.example.com",
			reverts:    []string{"revert 0"},
			errMessage: "allowing DNS over HTTPS traffic: test error",
		},
		"resolution_error": {
			allowErrs:  []error{nil},
			host:       "unknown.example.com",
			reverts:    []string{"revert 0"},
			errMessage: "resolving unknown.example.com: querying https://doh.example.com:",
		},
		"resolution_error_and_revert_error": {
			allowErrs:  []error{nil},
			host:       "unknown.example.com",
			revertErr:  errors.New("test revert error"),
			warning:    "removing temporary firewall rules: test revert error",
			reverts:    []string{"revert 0"},
			errMessage: "resolving unknown.example.com: querying https://doh.example.com:",
		},
		"allow_PureVPN_error": {
			allowErrs:  []error{nil, errors.New("test error")},
			host:       "auth.example.com",
			reverts:    []string{"revert 1", "revert 0"},
			errMessage: "allowing traffic to PureVPN website: test error",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			testDoHServer := newTestDoHServer(t, "auth.example.com")
			dohPort := serverPort(t, testDoHServer)
			rootCAs := x509.NewCertPool()
			rootCAs.AddCert(testDoHServer.Certificate())
			marks := &markRecorder{}
			dohURL := testCase.dohURL
			if dohURL == "" {
				dohURL = "https://doh.example.com:" + fmt.Sprint(dohPort) + "/dns-query"
			}
			preTunnel := preTunnelSettings{
				dohServers: []dohServer{
					{
						url: dohURL,
						ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
					},
				},
				hosts:       []string{testCase.host},
				port:        443,
				mark:        0x7075,
				dialControl: marks.control,
				rootCAs:     rootCAs,
			}
			ctx := context.Background()
			var reverts []string
			firewall := NewMockFirewall(ctrl)
			allowedAddrPorts := [...][]netip.AddrPort{
				{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), dohPort)},
				{netip.MustParseAddrPort("127.0.0.1:443")},
			}
			for i, allowErr := range testCase.allowErrs {
				revert := func(context.Context) error {
					reverts = append(reverts, fmt.Sprintf("revert %d", i))
					return testCase.revertErr
				}
				firewall.EXPECT().AllowOutputTemporarily(ctx, "tcp", uint32(0x7075), allowedAddrPorts[i]).
					Return(revert, allowErr)
			}
			logger := NewMockLogger(ctrl)
			if testCase.warning != "" {
				logger.EXPECT().Warn(testCase.warning)
			}

			client, resolve, cleanup, err := newPreTunnelHTTPClient(ctx, firewall, logger, preTunnel)

			assert.ErrorContains(t, err, testCase.errMessage)
			assert.Nil(t, client)
			assert.Nil(t, resolve)
			require.NotNil(t, cleanup)
			assert.Empty(t, reverts, "reverts must only be done by the cleanup")
			failedReverts := cleanup()
			assert.Equal(t, testCase.reverts, reverts)
			if testCase.revertErr != nil {
				assert.Len(t, failedReverts, 1)
			} else {
				assert.Empty(t, failedReverts)
			}
		})
	}
}

func Test_urlHostPort(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		rawURL     string
		hostPort   string
		port       uint16
		errMessage string
	}{
		"default_port": {
			rawURL:   "https://cloudflare-dns.com/dns-query",
			hostPort: "cloudflare-dns.com:443",
			port:     443,
		},
		"explicit_port": {
			rawURL:   "https://dns.google:8443/dns-query",
			hostPort: "dns.google:8443",
			port:     8443,
		},
		"invalid_port": {
			rawURL:     "https://dns.google:99999/dns-query",
			errMessage: "parsing port: ",
		},
		"invalid_URL": {
			rawURL:     "https://[::1/dns-query",
			errMessage: "parsing URL: ",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			hostPort, port, err := urlHostPort(testCase.rawURL)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, testCase.hostPort, hostPort)
			assert.Equal(t, testCase.port, port)
		})
	}
}

func Test_defaultPreTunnelSettings(t *testing.T) {
	t.Parallel()

	preTunnel := defaultPreTunnelSettings()

	assert.Equal(t, []string{"auth.purevpn.com", "my.purevpn.com"}, preTunnel.hosts)
	assert.Equal(t, uint16(443), preTunnel.port)
	assert.NotZero(t, preTunnel.mark)
	assert.NotNil(t, preTunnel.dialControl)
	assert.Nil(t, preTunnel.rootCAs)
	require.Len(t, preTunnel.dohServers, 2)
	for _, server := range preTunnel.dohServers {
		assert.NotEmpty(t, server.ips)
		for _, ip := range server.ips {
			assert.True(t, ip.Is4())
		}
	}
}

func Test_newPreTunnelMark(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		randomValues []uint32
		mark         uint32
	}{
		"first_value": {
			randomValues: []uint32{0x7075},
			mark:         0x7075,
		},
		"reserved_values_skipped": {
			randomValues: []uint32{0, 0x567, 4545, 51820, 0x7075},
			mark:         0x7075,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			calls := 0
			randomUint32 := func() uint32 {
				value := testCase.randomValues[calls]
				calls++
				return value
			}

			mark := newPreTunnelMark(randomUint32)

			assert.Equal(t, testCase.mark, mark)
			assert.Equal(t, len(testCase.randomValues), calls)
		})
	}
}

func Test_mustHost(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "auth.example.com", mustHost("https://auth.example.com:8443/path"))
	assert.Panics(t, func() { mustHost("://invalid") })
}

func Test_newPinnedTransport_dialErrors(t *testing.T) {
	t.Parallel()

	// Find two local TCP ports with nothing listening on them.
	closedAddrPorts := make([]netip.AddrPort, 2)
	for i := range closedAddrPorts {
		listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		require.NoError(t, err)
		closedAddrPorts[i] = netip.MustParseAddrPort(listener.Addr().String())
		require.NoError(t, listener.Close())
	}
	addresses := map[string][]netip.AddrPort{"host.example.com:443": closedAddrPorts}
	transport := newPinnedTransport(&net.Dialer{}, addresses, nil)
	t.Cleanup(transport.CloseIdleConnections)

	conn, err := transport.DialContext(context.Background(), "tcp", "host.example.com:443")

	assert.Nil(t, conn)
	require.Error(t, err)
	for _, addrPort := range closedAddrPorts {
		assert.ErrorContains(t, err, "dial tcp "+addrPort.String()+": connect: connection refused")
	}
}
