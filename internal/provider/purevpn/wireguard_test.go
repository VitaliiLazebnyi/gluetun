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
	"go.uber.org/mock/gomock"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const testServerPublicKey = "Y0QnWR6mhgxOjNkPUkRdPYKYrB+pERhKFAuhkBapHw8="

// testJWT is an access token JWT expiring in 2100.
const testJWT = "eyJhbGciOiJub25lIn0.eyJleHAiOjQxMDI0NDQ4MDB9.sig"

// fakeAPI serves the member area API endpoints, accepting only
// the access token given, and records the client public keys.
type fakeAPI struct {
	token    string
	endpoint string
	// loginError is the error message shown on the login page, if any.
	loginError   string
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
		page := `<form action="/oauth2/authorize" method="post">` +
			`<input name="loginId"><input name="password"></form>`
		if f.loginError != "" {
			page += `<div class="error">` + f.loginError + `</div>`
		}
		_, _ = w.Write([]byte(page))
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

// fakeNetwork is a restricted network using the HTTP client of a test
// server, recording the hostnames opened and the cleanups done.
type fakeNetwork struct {
	httpClient *http.Client
	openErr    error
	// cleanupErr is returned by the first cleanup only.
	cleanupErr error

	mutex     sync.Mutex
	hostnames []string
	openCtx   context.Context
	cleanups  uint
}

func (n *fakeNetwork) OpenHTTPSByHostname(ctx context.Context, hostname string) (
	*http.Client, func() error, error,
) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.hostnames = append(n.hostnames, hostname)
	n.openCtx = ctx
	if n.openErr != nil {
		return nil, nil, n.openErr
	}
	cleanup := func() error {
		n.mutex.Lock()
		defer n.mutex.Unlock()
		n.cleanups++
		if n.cleanups == 1 {
			return n.cleanupErr
		}
		return nil
	}
	return n.httpClient, cleanup, nil
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

func (n *fakeNetwork) opened() (count uint, cleanups uint) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return uint(len(n.hostnames)), n.cleanups
}

// newTestServer returns a test HTTPS server for the API given,
// and a restricted network reaching it.
func newTestServer(t *testing.T, api *fakeAPI) (server *httptest.Server, network *fakeNetwork) {
	t.Helper()
	server = httptest.NewTLSServer(api)
	t.Cleanup(server.Close)
	return server, &fakeNetwork{httpClient: server.Client()}
}

func newTestFetcher(t *testing.T, serverURL string) *wireguardFetcher {
	t.Helper()
	return &wireguardFetcher{
		statePath: filepath.Join(t.TempDir(), "state", "purevpn.json"),
		authURL:   serverURL,
		appURL:    serverURL,
		timeNow:   time.Now,
	}
}

func testVPNSettings(sessionToken, privateKey string) settings.VPN {
	return settings.VPN{
		Wireguard: settings.Wireguard{
			PrivateKey:                  new(privateKey),
			PersistentKeepaliveInterval: new(time.Duration(0)),
		},
		PureVPN: settings.PureVPN{
			Username:       new(""),
			Password:       new(""),
			TOTPSecret:     new(""),
			SessionToken:   new(sessionToken),
			Country:        "US",
			CityID:         new(uint(8778)),
			SubscriptionID: new(""),
			VPNUsername:    new(""),
		},
	}
}

func Test_wireguardFetcher_fetch(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	api := &fakeAPI{token: testJWT, endpoint: "us-ny.purevpn.net:51820"}
	server, network := newTestServer(t, api)

	logger := NewMockLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Info("generated a new Wireguard key pair for PureVPN"),
		logger.EXPECT().Debug("using PureVPN session token as access token"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
		logger.EXPECT().Info("PureVPN Wireguard server us-ny.purevpn.net (198.51.100.9:51820)"),
	)
	fetcher := newTestFetcher(t, server.URL)
	connection, err := fetcher.fetch(context.Background(),
		testVPNSettings(api.token, ""), network, logger)
	require.NoError(t, err)

	_, ok := network.openCtx.Deadline()
	assert.True(t, ok, "requests must be bounded by a timeout")
	opened, cleanups := network.opened()
	assert.Equal(t, api.requestsCount(), opened, "each request must use its own connection")
	assert.Equal(t, opened, cleanups, "each connection must be cleaned up")
	assert.Equal(t, strings.TrimPrefix(server.URL, "https://"), network.hostnames[0])

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
	restartedLogger := NewMockLogger(ctrl)
	gomock.InOrder(
		restartedLogger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
		restartedLogger.EXPECT().Info("PureVPN Wireguard server us-ny.purevpn.net (198.51.100.9:51820)"),
	)
	restarted := newTestFetcher(t, server.URL)
	restarted.statePath = fetcher.statePath
	second, err := restarted.fetch(context.Background(),
		testVPNSettings("", ""), network, restartedLogger)
	require.NoError(t, err)
	assert.Equal(t, connection.PrivateKey, second.PrivateKey)
}

func Test_wireguardFetcher_fetch_settingsPrivateKey(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	api := &fakeAPI{token: testJWT, endpoint: "203.0.113.5:51820"}
	server, network := newTestServer(t, api)

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	logger := NewMockLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Debug("using PureVPN session token as access token"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
		logger.EXPECT().Info("PureVPN Wireguard server 203.0.113.5 (203.0.113.5:51820)"),
	)
	fetcher := newTestFetcher(t, server.URL)
	connection, err := fetcher.fetch(context.Background(),
		testVPNSettings(api.token, key.String()), network, logger)
	require.NoError(t, err)
	assert.Equal(t, key.String(), connection.PrivateKey)
	assert.Equal(t, key.PublicKey().String(), api.clientPubKey)
	assert.Equal(t, netip.MustParseAddr("203.0.113.5"), connection.Connection.IP)
}

func Test_wireguardFetcher_fetch_canceledContext(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	api := &fakeAPI{token: testJWT, endpoint: "203.0.113.5:51820"}
	server, network := newTestServer(t, api)

	logger := NewMockLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Info("generated a new Wireguard key pair for PureVPN"),
		logger.EXPECT().Debug("using PureVPN session token as access token"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
	)
	fetcher := newTestFetcher(t, server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fetcher.fetch(ctx, testVPNSettings(api.token, ""), network, logger)
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, api.requestsCount())
}

func Test_wireguardFetcher_fetch_authError(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	api := &fakeAPI{token: testJWT, endpoint: "203.0.113.5:51820"}
	server, network := newTestServer(t, api)

	fetcher := newTestFetcher(t, server.URL)

	// No credentials and a rejected token: the login page is shown.
	logger := NewMockLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Info("generated a new Wireguard key pair for PureVPN"),
		logger.EXPECT().Debug("using PureVPN session token as single sign-on cookie"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
	)
	_, err := fetcher.fetch(context.Background(),
		testVPNSettings("rejected-token", ""), network, logger)
	require.ErrorContains(t, err, "PureVPN account username and password are not set")
	assert.ErrorContains(t, err, "change the PureVPN settings to retry")
	require.True(t, wgapi.IsAuthError(err))
	requestsAfterFirstFetch := api.requestsCount()
	require.NotZero(t, requestsAfterFirstFetch)

	// Same settings: the error is returned without contacting PureVPN
	// nor opening the firewall, even much later.
	fetcher.timeNow = func() time.Time { return time.Now().Add(1000 * time.Hour) }
	_, err = fetcher.fetch(context.Background(),
		testVPNSettings("rejected-token", ""), network, NewMockLogger(ctrl))
	require.ErrorContains(t, err, "not retrying with unchanged PureVPN settings: ")
	assert.ErrorContains(t, err, "PureVPN account username and password are not set")
	assert.Equal(t, requestsAfterFirstFetch, api.requestsCount())
	opened, _ := network.opened()
	assert.Equal(t, requestsAfterFirstFetch, opened)

	// Changed settings: PureVPN is contacted again.
	logger = NewMockLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Debug("using PureVPN session token as access token"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
		logger.EXPECT().Info("PureVPN Wireguard server 203.0.113.5 (203.0.113.5:51820)"),
	)
	_, err = fetcher.fetch(context.Background(),
		testVPNSettings(api.token, ""), network, logger)
	require.NoError(t, err)
	assert.Greater(t, api.requestsCount(), requestsAfterFirstFetch)
}

func Test_wireguardFetcher_fetch_captchaCooldown(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	api := &fakeAPI{token: testJWT, endpoint: "203.0.113.5:51820", loginError: "Please complete the captcha"}
	server, network := newTestServer(t, api)

	fetcher := newTestFetcher(t, server.URL)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fetcher.timeNow = func() time.Time { return start }
	vpnSettings := testVPNSettings("", "")
	vpnSettings.PureVPN.Username = new("user@example.com")
	vpnSettings.PureVPN.Password = new("password")

	logger := NewMockLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Info("generated a new Wireguard key pair for PureVPN"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
	)
	_, err := fetcher.fetch(context.Background(), vpnSettings, network, logger)
	require.True(t, wgapi.IsCaptchaError(err))
	assert.False(t, wgapi.IsAuthError(err))
	assert.ErrorContains(t, err, "log in once from a browser or set a session token")
	assert.ErrorContains(t, err, " - not contacting PureVPN again before 2026-01-01T01:00:00Z, "+
		"unless the PureVPN settings change")
	requestsAfterFirstFetch := api.requestsCount()
	require.NotZero(t, requestsAfterFirstFetch)

	// Same settings within the cooldown: PureVPN is not contacted.
	fetcher.timeNow = func() time.Time { return start.Add(time.Hour - time.Nanosecond) }
	_, err = fetcher.fetch(context.Background(), vpnSettings, network, NewMockLogger(ctrl))
	require.ErrorContains(t, err, "not retrying with unchanged PureVPN settings: ")
	assert.True(t, wgapi.IsCaptchaError(err))
	assert.Equal(t, requestsAfterFirstFetch, api.requestsCount())
	opened, _ := network.opened()
	assert.Equal(t, requestsAfterFirstFetch, opened)

	// Same settings after the cooldown: PureVPN is contacted again.
	fetcher.timeNow = func() time.Time { return start.Add(time.Hour) }
	logger = NewMockLogger(ctrl)
	logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778")
	_, err = fetcher.fetch(context.Background(), vpnSettings, network, logger)
	assert.ErrorContains(t, err, " - not contacting PureVPN again before 2026-01-01T02:00:00Z, ")
	requestsAfterSecondFetch := api.requestsCount()
	assert.Greater(t, requestsAfterSecondFetch, requestsAfterFirstFetch)

	// Changed settings within the cooldown: PureVPN is contacted again.
	vpnSettings.PureVPN.Password = new("other-password")
	logger = NewMockLogger(ctrl)
	logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778")
	_, err = fetcher.fetch(context.Background(), vpnSettings, network, logger)
	assert.True(t, wgapi.IsCaptchaError(err))
	assert.Greater(t, api.requestsCount(), requestsAfterSecondFetch)
}

func Test_wireguardFetcher_fetch_cleanupError(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	api := &fakeAPI{token: testJWT, endpoint: "203.0.113.5:51820"}
	server, network := newTestServer(t, api)
	// For example the firewall got disabled during the fetch,
	// so removing the firewall rule fails.
	network.cleanupErr = errors.New("test error")

	logger := NewMockLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Info("generated a new Wireguard key pair for PureVPN"),
		logger.EXPECT().Debug("using PureVPN session token as access token"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
		logger.EXPECT().Info("PureVPN Wireguard server 203.0.113.5 (203.0.113.5:51820)"),
		logger.EXPECT().Warn("cleaning up connections to PureVPN: test error"),
	)
	fetcher := newTestFetcher(t, server.URL)

	_, err := fetcher.fetch(context.Background(), testVPNSettings(api.token, ""), network, logger)

	assert.NoError(t, err)
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
		debug        string
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
			debug: "using PureVPN session token as single sign-on cookie",
			session: wgapi.Session{
				AuthCookies: map[string]string{"fusionauth.sso": "sso-cookie-value", "fusionauth.trust": "trusted"},
			},
			appliedHash: true,
		},
		"sso_token_without_cookies": {
			token:       "sso-cookie-value",
			debug:       "using PureVPN session token as single sign-on cookie",
			session:     wgapi.Session{AuthCookies: map[string]string{"fusionauth.sso": "sso-cookie-value"}},
			appliedHash: true,
		},
		"jwt_token_keeps_cookies": {
			initialState: wireguardState{Session: wgapi.Session{
				AccessToken: "old-access-token",
				AuthCookies: map[string]string{"fusionauth.sso": "sso", "fusionauth.trust": "trusted"},
			}},
			token: jwt,
			debug: "using PureVPN session token as access token",
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
			ctrl := gomock.NewController(t)

			logger := NewMockLogger(ctrl)
			if testCase.debug != "" {
				logger.EXPECT().Debug(testCase.debug)
			}
			fetcher := &wireguardFetcher{state: testCase.initialState}
			fetcher.applySessionToken(testCase.token, logger)
			assert.Equal(t, testCase.session, fetcher.state.Session)
			assert.Equal(t, testCase.appliedHash, fetcher.state.SessionTokenHash != "")

			// A refreshed session is not overwritten by the same token.
			fetcher.state.Session = wgapi.Session{AccessToken: "refreshed"}
			fetcher.applySessionToken(testCase.token, logger)
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
		// warning returns the warning expected for the state file path given, if any.
		warning func(statePath string) string
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
			warning: func(statePath string) string {
				return "saving PureVPN state, the next restart will need to log in again: " +
					"creating directory: mkdir " + filepath.Dir(statePath) + ": not a directory"
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			statePath := testCase.makeStatePath(t)
			logger := NewMockLogger(ctrl)
			if testCase.warning != nil {
				logger.EXPECT().Warn(testCase.warning(statePath))
			}
			fetcher := &wireguardFetcher{statePath: statePath, state: state}

			fetcher.saveState(logger)

			if testCase.warning != nil {
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
		content     *string
		isDirectory bool
		state       wireguardState
		warning     func(statePath string) string
	}{
		"no_file": {},
		"path_is_directory": {
			isDirectory: true,
			warning: func(statePath string) string {
				return "reading PureVPN state file: read " + statePath + ": is a directory"
			},
		},
		"valid_file": {
			content: new(`{"private_key":"key","session":{"access_token":"token"}}`),
			state:   wireguardState{PrivateKey: "key", Session: wgapi.Session{AccessToken: "token"}},
		},
		"corrupt_file": {
			content: new(`{"private_key":"key",`),
			warning: func(string) string {
				return "decoding PureVPN state file, ignoring it: unexpected end of JSON input"
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			statePath := filepath.Join(t.TempDir(), "state.json")
			switch {
			case testCase.content != nil:
				err := os.WriteFile(statePath, []byte(*testCase.content), 0o600)
				require.NoError(t, err)
			case testCase.isDirectory:
				err := os.Mkdir(statePath, 0o700)
				require.NoError(t, err)
			}
			logger := NewMockLogger(ctrl)
			if testCase.warning != nil {
				logger.EXPECT().Warn(testCase.warning(statePath))
			}
			fetcher := &wireguardFetcher{statePath: statePath}

			fetcher.loadState(logger)
			fetcher.loadState(logger) // loaded only once

			assert.Equal(t, testCase.state, fetcher.state)
			assert.True(t, fetcher.stateLoaded)
		})
	}
}

func Test_writeFileAtomically_renameError(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	err := os.Mkdir(path, 0o700) // renaming a file over a directory fails
	require.NoError(t, err)

	err = writeFileAtomically(path, []byte("data"))

	assert.ErrorContains(t, err, "renaming temporary file: ")
	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	require.Len(t, entries, 1, "temporary file must be removed")
	assert.Equal(t, "state.json", entries[0].Name())
	assert.True(t, entries[0].IsDir())
}

func Test_wireguardFetcher_fetch_errors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		privateKey    string
		endpoint      string
		openErr       error
		modifyFetcher func(fetcher *wireguardFetcher)
		makeLogger    func(ctrl *gomock.Controller) *MockLogger
		errMessage    string
	}{
		"invalid_settings_private_key": {
			privateKey: "invalid",
			makeLogger: NewMockLogger,
			errMessage: "parsing Wireguard private key: wgtypes: failed to parse base64-encoded key: " +
				"illegal base64 data at input byte 4",
		},
		"invalid_auth_url": {
			modifyFetcher: func(fetcher *wireguardFetcher) {
				fetcher.authURL = "://invalid"
			},
			makeLogger: func(ctrl *gomock.Controller) *MockLogger {
				logger := NewMockLogger(ctrl)
				logger.EXPECT().Info("generated a new Wireguard key pair for PureVPN")
				logger.EXPECT().Debug("using PureVPN session token as access token")
				return logger
			},
			errMessage: `creating PureVPN client: parsing auth URL: parse "://invalid": missing protocol scheme`,
		},
		"open_https_error": {
			openErr: errors.New("test error"),
			makeLogger: func(ctrl *gomock.Controller) *MockLogger {
				logger := NewMockLogger(ctrl)
				gomock.InOrder(
					logger.EXPECT().Info("generated a new Wireguard key pair for PureVPN"),
					logger.EXPECT().Debug("using PureVPN session token as access token"),
					// City ID 0 lets PureVPN pick a city in the country.
					logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US"),
				)
				return logger
			},
			errMessage: "opening restricted HTTPS connection: test error",
		},
		"not_https_url": {
			modifyFetcher: func(fetcher *wireguardFetcher) {
				fetcher.appURL = "http://127.0.0.1:1"
			},
			makeLogger: func(ctrl *gomock.Controller) *MockLogger {
				logger := NewMockLogger(ctrl)
				gomock.InOrder(
					logger.EXPECT().Info("generated a new Wireguard key pair for PureVPN"),
					logger.EXPECT().Debug("using PureVPN session token as access token"),
					// City ID 0 lets PureVPN pick a city in the country.
					logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US"),
				)
				return logger
			},
			errMessage: `URL scheme "http" is not https`,
		},
		"endpoint_resolution_error": {
			endpoint: "unknown.purevpn.net:51820",
			makeLogger: func(ctrl *gomock.Controller) *MockLogger {
				logger := NewMockLogger(ctrl)
				gomock.InOrder(
					logger.EXPECT().Info("generated a new Wireguard key pair for PureVPN"),
					logger.EXPECT().Debug("using PureVPN session token as access token"),
					// City ID 0 lets PureVPN pick a city in the country.
					logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US"),
				)
				return logger
			},
			errMessage: "resolving Wireguard endpoint: unknown host unknown.purevpn.net",
		},
		"endpoint_without_address": {
			endpoint: "empty.purevpn.net:51820",
			makeLogger: func(ctrl *gomock.Controller) *MockLogger {
				logger := NewMockLogger(ctrl)
				gomock.InOrder(
					logger.EXPECT().Info("generated a new Wireguard key pair for PureVPN"),
					logger.EXPECT().Debug("using PureVPN session token as access token"),
					// City ID 0 lets PureVPN pick a city in the country.
					logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US"),
				)
				return logger
			},
			errMessage: "no IP address found for Wireguard endpoint empty.purevpn.net",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			endpoint := testCase.endpoint
			if endpoint == "" {
				endpoint = "us-ny.purevpn.net:51820"
			}
			api := &fakeAPI{token: testJWT, endpoint: endpoint}
			server, network := newTestServer(t, api)
			network.openErr = testCase.openErr

			fetcher := newTestFetcher(t, server.URL)
			if testCase.modifyFetcher != nil {
				testCase.modifyFetcher(fetcher)
			}
			vpnSettings := testVPNSettings(api.token, testCase.privateKey)
			*vpnSettings.PureVPN.CityID = 0

			connection, err := fetcher.fetch(context.Background(), vpnSettings, network, testCase.makeLogger(ctrl))

			assert.ErrorContains(t, err, testCase.errMessage)
			assert.Equal(t, models.WireguardConnection{}, connection)
		})
	}
}

func Test_writeFileAtomically_createTempError(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	// The temporary file name is longer than the 255 bytes file name limit.
	path := filepath.Join(directory, strings.Repeat("a", 250))

	err := writeFileAtomically(path, []byte("data"))

	assert.ErrorContains(t, err, "creating temporary file: ")
	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	assert.Empty(t, entries)
}
