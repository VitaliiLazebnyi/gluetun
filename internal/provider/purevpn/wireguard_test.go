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

// recordingLogger records warning messages.
type recordingLogger struct {
	mutex sync.Mutex
	warns []string
}

func (*recordingLogger) Debug(string) {}
func (*recordingLogger) Info(string)  {}
func (l *recordingLogger) Warn(message string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.warns = append(l.warns, message)
}

func (l *recordingLogger) warnings() []string {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return append([]string(nil), l.warns...)
}

// fakeAPI serves the member area API endpoints, accepting only
// the access token given, and records the client public keys.
type fakeAPI struct {
	token        string
	endpoint     string
	mutex        sync.Mutex
	clientPubKey string
	requests     uint
}

func (f *fakeAPI) requestsCount() uint {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.requests
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mutex.Lock()
	f.requests++
	f.mutex.Unlock()
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

// testFetcher is a fetcher using a fake HTTP client constructor,
// counting how many times it is called.
type testFetcher struct {
	*wireguardFetcher
	mutex          sync.Mutex
	newClientCalls uint
	newClientCtx   context.Context
}

func (f *testFetcher) newClientCallsCount() uint {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.newClientCalls
}

func newTestFetcher(t *testing.T, serverURL string) *testFetcher {
	t.Helper()
	fetcher := &testFetcher{}
	fetcher.wireguardFetcher = &wireguardFetcher{
		statePath: filepath.Join(t.TempDir(), "state", "purevpn.json"),
		authURL:   serverURL,
		appURL:    serverURL,
		newHTTPClient: func(ctx context.Context, _ Firewall, _ Logger) (*http.Client,
			func(ctx context.Context, host string) ([]netip.Addr, error), func(), error,
		) {
			fetcher.mutex.Lock()
			fetcher.newClientCalls++
			fetcher.newClientCtx = ctx
			fetcher.mutex.Unlock()
			resolve := func(_ context.Context, host string) ([]netip.Addr, error) {
				if host == "us-ny.purevpn.net" {
					return []netip.Addr{netip.MustParseAddr("198.51.100.9")}, nil
				}
				return nil, errors.New("unknown host " + host)
			}
			return &http.Client{Timeout: 5 * time.Second}, resolve, func() {}, nil
		},
	}
	return fetcher
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
		testVPNSettings(api.token, ""), nil, &recordingLogger{})
	require.NoError(t, err)

	deadline, ok := fetcher.newClientCtx.Deadline()
	require.True(t, ok, "the fetch must be bounded by a timeout")
	assert.WithinDuration(t, time.Now().Add(2*time.Minute), deadline, 10*time.Second)

	key, err := wgtypes.ParseKey(connection.PrivateKey)
	require.NoError(t, err)
	assert.Equal(t, key.PublicKey().String(), api.clientPubKey,
		"the generated key public key must be sent to PureVPN")
	assert.Equal(t, models.WireguardConnection{
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
		testVPNSettings("", ""), nil, &recordingLogger{})
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
		testVPNSettings(api.token, key.String()), nil, &recordingLogger{})
	require.NoError(t, err)
	assert.Equal(t, key.String(), connection.PrivateKey)
	assert.Equal(t, key.PublicKey().String(), api.clientPubKey)
	assert.Equal(t, netip.MustParseAddr("203.0.113.5"), connection.Connection.IP)
}

func Test_wireguardFetcher_fetch_canceledContext(t *testing.T) {
	t.Parallel()

	api := &fakeAPI{token: testJWT, endpoint: "203.0.113.5:51820"}
	server := httptest.NewServer(api)
	defer server.Close()

	fetcher := newTestFetcher(t, server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fetcher.fetch(ctx, testVPNSettings(api.token, ""), nil, &recordingLogger{})
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, api.requestsCount())
}

func Test_wireguardFetcher_fetch_authError(t *testing.T) {
	t.Parallel()

	api := &fakeAPI{token: testJWT, endpoint: "203.0.113.5:51820"}
	server := httptest.NewServer(api)
	defer server.Close()

	fetcher := newTestFetcher(t, server.URL)

	// No credentials and a rejected token: the login page is shown.
	_, err := fetcher.fetch(context.Background(),
		testVPNSettings("rejected-token", ""), nil, &recordingLogger{})
	require.ErrorContains(t, err, "PureVPN account username and password are not set")
	assert.ErrorContains(t, err, "change the PureVPN settings to retry")
	require.True(t, wgapi.IsAuthError(err))
	requestsAfterFirstFetch := api.requestsCount()
	require.NotZero(t, requestsAfterFirstFetch)
	assert.Equal(t, uint(1), fetcher.newClientCallsCount())

	// Same settings: the error is returned without contacting PureVPN
	// nor opening the firewall.
	_, err = fetcher.fetch(context.Background(),
		testVPNSettings("rejected-token", ""), nil, &recordingLogger{})
	require.ErrorContains(t, err, "not retrying with unchanged PureVPN settings: ")
	assert.ErrorContains(t, err, "PureVPN account username and password are not set")
	assert.Equal(t, requestsAfterFirstFetch, api.requestsCount())
	assert.Equal(t, uint(1), fetcher.newClientCallsCount())

	// Changed settings: PureVPN is contacted again.
	_, err = fetcher.fetch(context.Background(),
		testVPNSettings(api.token, ""), nil, &recordingLogger{})
	require.NoError(t, err)
	assert.Greater(t, api.requestsCount(), requestsAfterFirstFetch)
	assert.Equal(t, uint(2), fetcher.newClientCallsCount())
}

func Test_settingsFingerprint(t *testing.T) {
	t.Parallel()

	base := testVPNSettings("token", "").PureVPN
	baseFingerprint := settingsFingerprint(base)
	assert.Equal(t, baseFingerprint, settingsFingerprint(testVPNSettings("token", "").PureVPN))

	testCases := map[string]func(purevpnSettings *settings.PureVPN){
		"username":        func(s *settings.PureVPN) { s.Username = new("user") },
		"password":        func(s *settings.PureVPN) { s.Password = new("password") },
		"totp_secret":     func(s *settings.PureVPN) { s.TOTPSecret = new("JBSWY3DP") },
		"session_token":   func(s *settings.PureVPN) { s.SessionToken = new("other") },
		"country":         func(s *settings.PureVPN) { s.Country = "GB" },
		"city_id":         func(s *settings.PureVPN) { s.CityID = new(uint(1)) },
		"subscription_id": func(s *settings.PureVPN) { s.SubscriptionID = new("s2") },
		"vpn_username":    func(s *settings.PureVPN) { s.VPNUsername = new("purevpn0s2") },
	}

	for name, modify := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			modified := testVPNSettings("token", "").PureVPN
			modify(&modified)
			assert.NotEqual(t, baseFingerprint, settingsFingerprint(modified))
		})
	}
}

func Test_wireguardFetcher_applySessionToken(t *testing.T) {
	t.Parallel()

	const jwt = "eyJhbGciOiJub25lIn0.eyJleHAiOjQxMDI0NDQ4MDB9.sig"
	testCases := map[string]struct {
		initialState wireguardState
		token        string
		session      wgapi.Session
		appliedHash  bool
	}{
		"empty_token": {
			initialState: wireguardState{Session: wgapi.Session{AccessToken: "existing"}},
			session:      wgapi.Session{AccessToken: "existing"},
		},
		"sso_token_keeps_other_cookies": {
			initialState: wireguardState{Session: wgapi.Session{
				AccessToken: "old-access-token",
				AuthCookies: map[string]string{"fusionauth.sso": "old", "fusionauth.trust": "trusted"},
			}},
			token: "sso-cookie-value",
			session: wgapi.Session{
				AuthCookies: map[string]string{"fusionauth.sso": "sso-cookie-value", "fusionauth.trust": "trusted"},
			},
			appliedHash: true,
		},
		"sso_token_without_cookies": {
			token:       "sso-cookie-value",
			session:     wgapi.Session{AuthCookies: map[string]string{"fusionauth.sso": "sso-cookie-value"}},
			appliedHash: true,
		},
		"jwt_token_keeps_cookies": {
			initialState: wireguardState{Session: wgapi.Session{
				AccessToken: "old-access-token",
				AuthCookies: map[string]string{"fusionauth.sso": "sso", "fusionauth.trust": "trusted"},
			}},
			token: jwt,
			session: wgapi.Session{
				AccessToken: jwt,
				AuthCookies: map[string]string{"fusionauth.sso": "sso", "fusionauth.trust": "trusted"},
			},
			appliedHash: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fetcher := &wireguardFetcher{state: testCase.initialState}
			fetcher.applySessionToken(testCase.token, &recordingLogger{})
			assert.Equal(t, testCase.session, fetcher.state.Session)
			assert.Equal(t, testCase.appliedHash, fetcher.state.SessionTokenHash != "")

			// A refreshed session is not overwritten by the same token.
			fetcher.state.Session = wgapi.Session{AccessToken: "refreshed"}
			fetcher.applySessionToken(testCase.token, &recordingLogger{})
			assert.Equal(t, wgapi.Session{AccessToken: "refreshed"}, fetcher.state.Session)
		})
	}
}

func Test_wireguardFetcher_saveState(t *testing.T) {
	t.Parallel()

	state := wireguardState{PrivateKey: "key", Session: wgapi.Session{AccessToken: "token"}}
	expectedData, err := json.MarshalIndent(state, "", "  ") //nolint:gosec
	require.NoError(t, err)

	testCases := map[string]struct {
		// makeStatePath creates files as needed and returns the state file path.
		makeStatePath func(t *testing.T) string
		warnings      []string
	}{
		"new_file_in_new_directory": {
			makeStatePath: func(t *testing.T) string {
				t.Helper()
				return filepath.Join(t.TempDir(), "subdirectory", "state.json")
			},
		},
		"existing_file_with_loose_permissions": {
			makeStatePath: func(t *testing.T) string {
				t.Helper()
				path := filepath.Join(t.TempDir(), "state.json")
				err := os.WriteFile(path, []byte("old content"), 0o644) //nolint:gosec
				require.NoError(t, err)
				err = os.Chmod(path, 0o644)
				require.NoError(t, err)
				return path
			},
		},
		"directory_is_a_file": {
			makeStatePath: func(t *testing.T) string {
				t.Helper()
				parent := filepath.Join(t.TempDir(), "file")
				err := os.WriteFile(parent, nil, 0o600)
				require.NoError(t, err)
				return filepath.Join(parent, "state.json")
			},
			warnings: []string{"saving PureVPN state, the next restart will need to log in again: " +
				"creating directory: mkdir "},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			statePath := testCase.makeStatePath(t)
			logger := &recordingLogger{}
			fetcher := &wireguardFetcher{statePath: statePath, state: state}

			fetcher.saveState(logger)

			warnings := logger.warnings()
			require.Len(t, warnings, len(testCase.warnings))
			for i, warning := range testCase.warnings {
				assert.Contains(t, warnings[i], warning)
			}
			if len(testCase.warnings) > 0 {
				return
			}

			data, err := os.ReadFile(statePath)
			require.NoError(t, err)
			assert.Equal(t, expectedData, data)
			info, err := os.Stat(statePath)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
			entries, err := os.ReadDir(filepath.Dir(statePath))
			require.NoError(t, err)
			require.Len(t, entries, 1, "temporary file must not be left behind")
			assert.Equal(t, filepath.Base(statePath), entries[0].Name())
		})
	}
}

func Test_wireguardFetcher_loadState(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		content  *string
		state    wireguardState
		warnings []string
	}{
		"no_file": {},
		"valid_file": {
			content: new(`{"private_key":"key","session":{"access_token":"token"}}`),
			state:   wireguardState{PrivateKey: "key", Session: wgapi.Session{AccessToken: "token"}},
		},
		"corrupt_file": {
			content:  new(`{"private_key":"key",`),
			warnings: []string{"decoding PureVPN state file, ignoring it: unexpected end of JSON input"},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			statePath := filepath.Join(t.TempDir(), "state.json")
			if testCase.content != nil {
				err := os.WriteFile(statePath, []byte(*testCase.content), 0o600)
				require.NoError(t, err)
			}
			logger := &recordingLogger{}
			fetcher := &wireguardFetcher{statePath: statePath}

			fetcher.loadState(logger)

			assert.Equal(t, testCase.state, fetcher.state)
			assert.Equal(t, testCase.warnings, logger.warnings())
		})
	}
}
