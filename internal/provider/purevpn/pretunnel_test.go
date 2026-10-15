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

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeFirewall records AllowOutputTemporarily and revert calls.
type fakeFirewall struct {
	// allowErrs are the errors to return for each AllowOutputTemporarily call.
	allowErrs []error
	// revertErrs are the errors to return for each revert, indexed by
	// AllowOutputTemporarily call index.
	revertErrs []error

	mutex   sync.Mutex
	allowed []string
	reverts []int
}

func (f *fakeFirewall) AllowOutputTemporarily(_ context.Context, protocol string, mark uint32,
	addrPorts []netip.AddrPort,
) (revert func(ctx context.Context) error, err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	index := len(f.allowed)
	f.allowed = append(f.allowed, fmt.Sprintf("%s mark %d %v", protocol, mark, addrPorts))
	revert = func(context.Context) error {
		f.mutex.Lock()
		defer f.mutex.Unlock()
		f.reverts = append(f.reverts, index)
		if index < len(f.revertErrs) {
			return f.revertErrs[index]
		}
		return nil
	}
	if index < len(f.allowErrs) {
		err = f.allowErrs[index]
	}
	return revert, err
}

func (f *fakeFirewall) calls() (allowed []string, reverts []int) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return append([]string(nil), f.allowed...), append([]int(nil), f.reverts...)
}

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

	testDoHServer := newTestDoHServer(t, "auth.example.com")
	dohPort := serverPort(t, testDoHServer)
	purevpnServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("purevpn"))
	}))
	defer purevpnServer.Close()
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
	firewall := &fakeFirewall{revertErrs: []error{nil, errors.New("test revert error")}}
	logger := &recordingLogger{}

	client, resolve, cleanup, err := newPreTunnelHTTPClient(context.Background(), firewall, logger, preTunnel)
	require.NoError(t, err)

	allowed, reverts := firewall.calls()
	assert.Equal(t, []string{
		fmt.Sprintf("tcp mark 28789 [127.0.0.1:%d]", dohPort),
		fmt.Sprintf("tcp mark 28789 [127.0.0.1:%d]", purevpnPort),
	}, allowed)
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
		cleanup()
		_, reverts = firewall.calls()
		assert.Equal(t, []int{1, 0}, reverts, "reverts must be done in reverse order")
		assert.Equal(t, []string{"removing temporary firewall rules: test revert error"}, logger.warnings())
	})
}

func Test_newPreTunnelHTTPClient_errors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		allowErrs  []error
		host       string
		allowed    int
		reverts    []int
		errMessage string
	}{
		"allow_DoH_error": {
			allowErrs:  []error{errors.New("test error")},
			host:       "auth.example.com",
			allowed:    1,
			reverts:    []int{0},
			errMessage: "allowing DNS over HTTPS traffic: test error",
		},
		"resolution_error": {
			host:       "unknown.example.com",
			allowed:    1,
			reverts:    []int{0},
			errMessage: "resolving unknown.example.com: querying https://doh.example.com:",
		},
		"allow_PureVPN_error": {
			allowErrs:  []error{nil, errors.New("test error")},
			host:       "auth.example.com",
			allowed:    2,
			reverts:    []int{1, 0},
			errMessage: "allowing traffic to PureVPN website: test error",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			testDoHServer := newTestDoHServer(t, "auth.example.com")
			rootCAs := x509.NewCertPool()
			rootCAs.AddCert(testDoHServer.Certificate())
			marks := &markRecorder{}
			preTunnel := preTunnelSettings{
				dohServers: []dohServer{
					{
						url: "https://doh.example.com:" + fmt.Sprint(serverPort(t, testDoHServer)) + "/dns-query",
						ips: []netip.Addr{netip.MustParseAddr("127.0.0.1")},
					},
				},
				hosts:       []string{testCase.host},
				port:        443,
				mark:        0x7075,
				dialControl: marks.control,
				rootCAs:     rootCAs,
			}
			firewall := &fakeFirewall{allowErrs: testCase.allowErrs}

			client, resolve, cleanup, err := newPreTunnelHTTPClient(context.Background(),
				firewall, &recordingLogger{}, preTunnel)

			assert.ErrorContains(t, err, testCase.errMessage)
			assert.Nil(t, client)
			assert.Nil(t, resolve)
			assert.Nil(t, cleanup)
			allowed, reverts := firewall.calls()
			assert.Len(t, allowed, testCase.allowed)
			assert.Equal(t, testCase.reverts, reverts)
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
	assert.NotEqual(t, preTunnel.mark, defaultPreTunnelSettings().mark, "mark must be random")
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

	reserved := map[uint32]struct{}{0: {}, 0x567: {}, 4545: {}, 51820: {}}
	for range 1000 {
		mark := newPreTunnelMark()
		_, isReserved := reserved[mark]
		assert.False(t, isReserved)
	}
}
