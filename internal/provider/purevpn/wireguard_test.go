package purevpn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/purevpn/wgapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const testServerPublicKey = "Y0QnWR6mhgxOjNkPUkRdPYKYrB+pERhKFAuhkBapHw8="

// testJWT is an access token JWT expiring in 2100.
const testJWT = "eyJhbGciOiJub25lIn0.eyJleHAiOjQxMDI0NDQ4MDB9.sig"

type noopLogger struct{}

func (noopLogger) Debug(string) {}
func (noopLogger) Info(string)  {}
func (noopLogger) Warn(string)  {}

// fakeAPI serves the member area API endpoints, accepting only
// the access token given, and records the client public keys.
type fakeAPI struct {
	token        string
	endpoint     string
	mutex        sync.Mutex
	clientPubKey string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		// Not logged in: show the login page, as the auth server would.
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<form action="/oauth2/authorize">` +
			`<input name="loginId"><input name="password"></form>`))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	_ = r.ParseForm()
	var body string
	switch r.URL.Path {
	case "/v2/api/subscription":
		body = `[{"id":"s1","state":"active","vpnusernames":["purevpn0s1"]}]`
	case "/v2/api/wireguard/get-encrypt-password":
		body = `{"encrypPass":"x"}`
	case "/v2/api/wireguard/get-wg-server":
		f.mutex.Lock()
		f.clientPubKey = r.PostForm.Get("sClientPublicKey")
		f.mutex.Unlock()
		config := "[Interface]\nAddress=172.21.7.9\n[Peer]\nPublicKey=" + testServerPublicKey +
			"\nEndpoint=" + f.endpoint + "\nPersistentKeepalive=21\n"
		configJSON, err := json.Marshal(config)
		if err != nil {
			panic(err)
		}
		body = `[{"wireguard_configuration":` + string(configJSON) + `}]`
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_, _ = w.Write([]byte(`{"status":true,"body":` + body + `}`))
}

func newTestFetcher(t *testing.T, serverURL string) *wireguardFetcher {
	t.Helper()
	return &wireguardFetcher{
		statePath: filepath.Join(t.TempDir(), "state", "purevpn.json"),
		authURL:   serverURL,
		appURL:    serverURL,
		newHTTPClient: func(_ context.Context, _ Firewall) (*http.Client,
			func(ctx context.Context, host string) ([]netip.Addr, error), func(), error,
		) {
			resolve := func(_ context.Context, host string) ([]netip.Addr, error) {
				if host == "us-ny.purevpn.net" {
					return []netip.Addr{netip.MustParseAddr("198.51.100.9")}, nil
				}
				return nil, errors.New("unknown host " + host)
			}
			return &http.Client{Timeout: 5 * time.Second}, resolve, func() {}, nil
		},
	}
}

func testVPNSettings(sessionToken, privateKey string) settings.VPN {
	empty := ""
	var cityID uint = 8778
	var keepalive time.Duration
	return settings.VPN{
		Wireguard: settings.Wireguard{
			PrivateKey:                  &privateKey,
			PersistentKeepaliveInterval: &keepalive,
		},
		PureVPN: settings.PureVPN{
			Username: &empty, Password: &empty, TOTPSecret: &empty,
			SessionToken:   &sessionToken,
			Country:        "US",
			CityID:         &cityID,
			SubscriptionID: &empty,
			VPNUsername:    &empty,
		},
	}
}

func Test_wireguardFetcher_fetch(t *testing.T) {
	t.Parallel()

	api := &fakeAPI{token: testJWT, endpoint: "us-ny.purevpn.net:51820"}
	server := httptest.NewServer(api)
	defer server.Close()

	fetcher := newTestFetcher(t, server.URL)
	connection, err := fetcher.fetch(context.Background(),
		testVPNSettings(api.token, ""), nil, noopLogger{})
	require.NoError(t, err)

	key, err := wgtypes.ParseKey(connection.PrivateKey)
	require.NoError(t, err)
	assert.Equal(t, key.PublicKey().String(), api.clientPubKey,
		"the generated key public key must be sent to PureVPN")
	assert.Equal(t, WireguardConnection{
		Connection: models.Connection{
			Type:       "wireguard",
			IP:         netip.MustParseAddr("198.51.100.9"),
			Port:       51820,
			Protocol:   constants.UDP,
			Hostname:   "us-ny.purevpn.net",
			ServerName: "us-ny.purevpn.net",
			PubKey:     testServerPublicKey,
		},
		PrivateKey:          connection.PrivateKey,
		Addresses:           []netip.Prefix{netip.MustParsePrefix("172.21.7.9/32")},
		PersistentKeepalive: 21 * time.Second,
	}, connection)

	// State is persisted with restrictive permissions.
	info, err := os.Stat(fetcher.statePath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	data, err := os.ReadFile(fetcher.statePath)
	require.NoError(t, err)
	var state wireguardState
	require.NoError(t, json.Unmarshal(data, &state))
	assert.Equal(t, connection.PrivateKey, state.PrivateKey)
	assert.Equal(t, api.token, state.Session.AccessToken)
	assert.NotEmpty(t, state.SessionTokenHash)
	assert.NotContains(t, string(data), "Bearer")

	// A restarted fetcher reuses the persisted key pair and session,
	// even without the session token in the settings.
	restarted := newTestFetcher(t, server.URL)
	restarted.statePath = fetcher.statePath
	second, err := restarted.fetch(context.Background(),
		testVPNSettings("", ""), nil, noopLogger{})
	require.NoError(t, err)
	assert.Equal(t, connection.PrivateKey, second.PrivateKey)
}

func Test_wireguardFetcher_fetch_settingsPrivateKey(t *testing.T) {
	t.Parallel()

	api := &fakeAPI{token: testJWT, endpoint: "203.0.113.5:51820"}
	server := httptest.NewServer(api)
	defer server.Close()

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	fetcher := newTestFetcher(t, server.URL)
	connection, err := fetcher.fetch(context.Background(),
		testVPNSettings(api.token, key.String()), nil, noopLogger{})
	require.NoError(t, err)
	assert.Equal(t, key.String(), connection.PrivateKey)
	assert.Equal(t, key.PublicKey().String(), api.clientPubKey)
	assert.Equal(t, netip.MustParseAddr("203.0.113.5"), connection.Connection.IP)
}

func Test_wireguardFetcher_fetch_authError(t *testing.T) {
	t.Parallel()

	api := &fakeAPI{token: "other-token", endpoint: "203.0.113.5:51820"}
	server := httptest.NewServer(api)
	defer server.Close()

	fetcher := newTestFetcher(t, server.URL)
	// No credentials and a rejected token: the login page is shown.
	_, err := fetcher.fetch(context.Background(),
		testVPNSettings("rejected-token", ""), nil, noopLogger{})
	require.ErrorContains(t, err, "PureVPN account username and password are not set")
	assert.True(t, strings.Contains(err.Error(), "fix the PureVPN settings"))
}

func Test_wireguardFetcher_applySessionToken(t *testing.T) {
	t.Parallel()

	fetcher := &wireguardFetcher{}
	fetcher.applySessionToken("sso-cookie-value", noopLogger{})
	assert.Equal(t, map[string]string{"fusionauth.sso": "sso-cookie-value"},
		fetcher.state.Session.AuthCookies)

	// A refreshed session is not overwritten by the same token.
	fetcher.state.Session = wgapi.Session{AccessToken: "refreshed"}
	fetcher.applySessionToken("sso-cookie-value", noopLogger{})
	assert.Equal(t, "refreshed", fetcher.state.Session.AccessToken)

	// A new JWT token replaces the session.
	jwt := "eyJhbGciOiJub25lIn0.eyJleHAiOjQxMDI0NDQ4MDB9.sig"
	fetcher.applySessionToken(jwt, noopLogger{})
	assert.Equal(t, wgapi.Session{AccessToken: jwt}, fetcher.state.Session)
}
