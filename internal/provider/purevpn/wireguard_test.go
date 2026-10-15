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
			func(ctx context.Context, host string) ([]netip.Addr, error),
			func() []func(ctx context.Context) error, error,
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
			cleanup := func() []func(ctx context.Context) error { return nil }
			return &http.Client{Timeout: 5 * time.Second}, resolve, cleanup, nil
		},
		timeNow: time.Now,
	}
	return fetcher
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
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)

	logger := NewMockLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Info("generated a new Wireguard key pair for PureVPN"),
		logger.EXPECT().Debug("using PureVPN session token as access token"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
		logger.EXPECT().Info("PureVPN Wireguard server us-ny.purevpn.net (198.51.100.9:51820)"),
	)
	fetcher := newTestFetcher(t, server.URL)
	connection, err := fetcher.fetch(context.Background(),
		testVPNSettings(api.token, ""), nil, logger)
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
	restartedLogger := NewMockLogger(ctrl)
	gomock.InOrder(
		restartedLogger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
		restartedLogger.EXPECT().Info("PureVPN Wireguard server us-ny.purevpn.net (198.51.100.9:51820)"),
	)
	restarted := newTestFetcher(t, server.URL)
	restarted.statePath = fetcher.statePath
	second, err := restarted.fetch(context.Background(),
		testVPNSettings("", ""), nil, restartedLogger)
	require.NoError(t, err)
	assert.Equal(t, connection.PrivateKey, second.PrivateKey)
}

func Test_wireguardFetcher_fetch_settingsPrivateKey(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	api := &fakeAPI{token: testJWT, endpoint: "203.0.113.5:51820"}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)

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
		testVPNSettings(api.token, key.String()), nil, logger)
	require.NoError(t, err)
	assert.Equal(t, key.String(), connection.PrivateKey)
	assert.Equal(t, key.PublicKey().String(), api.clientPubKey)
	assert.Equal(t, netip.MustParseAddr("203.0.113.5"), connection.Connection.IP)
}

func Test_wireguardFetcher_fetch_canceledContext(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	api := &fakeAPI{token: testJWT, endpoint: "203.0.113.5:51820"}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)

	logger := NewMockLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Info("generated a new Wireguard key pair for PureVPN"),
		logger.EXPECT().Debug("using PureVPN session token as access token"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
	)
	fetcher := newTestFetcher(t, server.URL)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fetcher.fetch(ctx, testVPNSettings(api.token, ""), nil, logger)
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, api.requestsCount())
}

func Test_wireguardFetcher_fetch_authError(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	api := &fakeAPI{token: testJWT, endpoint: "203.0.113.5:51820"}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)

	fetcher := newTestFetcher(t, server.URL)

	// No credentials and a rejected token: the login page is shown.
	logger := NewMockLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Info("generated a new Wireguard key pair for PureVPN"),
		logger.EXPECT().Debug("using PureVPN session token as single sign-on cookie"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
	)
	_, err := fetcher.fetch(context.Background(),
		testVPNSettings("rejected-token", ""), nil, logger)
	require.ErrorContains(t, err, "PureVPN account username and password are not set")
	assert.ErrorContains(t, err, "change the PureVPN settings to retry")
	require.True(t, wgapi.IsAuthError(err))
	requestsAfterFirstFetch := api.requestsCount()
	require.NotZero(t, requestsAfterFirstFetch)
	assert.Equal(t, uint(1), fetcher.newClientCallsCount())

	// Same settings: the error is returned without contacting PureVPN
	// nor opening the firewall, even much later.
	fetcher.timeNow = func() time.Time { return time.Now().Add(1000 * time.Hour) }
	_, err = fetcher.fetch(context.Background(),
		testVPNSettings("rejected-token", ""), nil, NewMockLogger(ctrl))
	require.ErrorContains(t, err, "not retrying with unchanged PureVPN settings: ")
	assert.ErrorContains(t, err, "PureVPN account username and password are not set")
	assert.Equal(t, requestsAfterFirstFetch, api.requestsCount())
	assert.Equal(t, uint(1), fetcher.newClientCallsCount())

	// Changed settings: PureVPN is contacted again.
	logger = NewMockLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Debug("using PureVPN session token as access token"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
		logger.EXPECT().Info("PureVPN Wireguard server 203.0.113.5 (203.0.113.5:51820)"),
	)
	_, err = fetcher.fetch(context.Background(),
		testVPNSettings(api.token, ""), nil, logger)
	require.NoError(t, err)
	assert.Greater(t, api.requestsCount(), requestsAfterFirstFetch)
	assert.Equal(t, uint(2), fetcher.newClientCallsCount())
}

func Test_wireguardFetcher_fetch_captchaCooldown(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	api := &fakeAPI{token: testJWT, endpoint: "203.0.113.5:51820", loginError: "Please complete the captcha"}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)

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
	_, err := fetcher.fetch(context.Background(), vpnSettings, nil, logger)
	require.True(t, wgapi.IsCaptchaError(err))
	assert.False(t, wgapi.IsAuthError(err))
	assert.ErrorContains(t, err, "log in once from a browser or set a session token")
	assert.ErrorContains(t, err, " - not contacting PureVPN again before 2026-01-01T01:00:00Z, "+
		"unless the PureVPN settings change")
	requestsAfterFirstFetch := api.requestsCount()
	require.NotZero(t, requestsAfterFirstFetch)

	// Same settings within the cooldown: PureVPN is not contacted.
	fetcher.timeNow = func() time.Time { return start.Add(time.Hour - time.Nanosecond) }
	_, err = fetcher.fetch(context.Background(), vpnSettings, nil, NewMockLogger(ctrl))
	require.ErrorContains(t, err, "not retrying with unchanged PureVPN settings: ")
	assert.True(t, wgapi.IsCaptchaError(err))
	assert.Equal(t, requestsAfterFirstFetch, api.requestsCount())
	assert.Equal(t, uint(1), fetcher.newClientCallsCount())

	// Same settings after the cooldown: PureVPN is contacted again.
	fetcher.timeNow = func() time.Time { return start.Add(time.Hour) }
	logger = NewMockLogger(ctrl)
	logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778")
	_, err = fetcher.fetch(context.Background(), vpnSettings, nil, logger)
	assert.ErrorContains(t, err, " - not contacting PureVPN again before 2026-01-01T02:00:00Z, ")
	requestsAfterSecondFetch := api.requestsCount()
	assert.Greater(t, requestsAfterSecondFetch, requestsAfterFirstFetch)
	assert.Equal(t, uint(2), fetcher.newClientCallsCount())

	// Changed settings within the cooldown: PureVPN is contacted again.
	vpnSettings.PureVPN.Password = new("other-password")
	logger = NewMockLogger(ctrl)
	logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778")
	_, err = fetcher.fetch(context.Background(), vpnSettings, nil, logger)
	assert.True(t, wgapi.IsCaptchaError(err))
	assert.Greater(t, api.requestsCount(), requestsAfterSecondFetch)
	assert.Equal(t, uint(3), fetcher.newClientCallsCount())
}

func Test_wireguardFetcher_fetch_retriesFailedReverts(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	revertErrs := [...]error{errors.New("test revert error"), nil}
	revertCalls := 0
	revert := func(context.Context) error {
		err := revertErrs[revertCalls]
		revertCalls++
		return err
	}
	cleanupCalls := 0
	fetcher := &wireguardFetcher{
		statePath: filepath.Join(t.TempDir(), "purevpn.json"),
		newHTTPClient: func(context.Context, Firewall, Logger) (*http.Client,
			func(ctx context.Context, host string) ([]netip.Addr, error),
			func() []func(ctx context.Context) error, error,
		) {
			cleanup := func() []func(ctx context.Context) error {
				cleanupCalls++
				if cleanupCalls == 1 {
					return []func(ctx context.Context) error{revert}
				}
				return nil
			}
			return nil, nil, cleanup, errors.New("test error")
		},
		timeNow: time.Now,
	}
	vpnSettings := testVPNSettings("", "")

	// The first fetch fails to remove the firewall rules.
	logger := NewMockLogger(ctrl)
	logger.EXPECT().Info("generated a new Wireguard key pair for PureVPN")
	_, err := fetcher.fetch(context.Background(), vpnSettings, nil, logger)
	require.EqualError(t, err, "preparing network access to PureVPN: test error")
	assert.Zero(t, revertCalls)

	// The second fetch fails again to remove them.
	logger = NewMockLogger(ctrl)
	logger.EXPECT().Warn("removing temporary firewall rules left by a previous attempt: test revert error")
	_, err = fetcher.fetch(context.Background(), vpnSettings, nil, logger)
	require.EqualError(t, err, "preparing network access to PureVPN: test error")
	assert.Equal(t, 1, revertCalls)

	// The third fetch removes them.
	logger = NewMockLogger(ctrl)
	logger.EXPECT().Info("removed temporary firewall rules left by a previous attempt")
	_, err = fetcher.fetch(context.Background(), vpnSettings, nil, logger)
	require.EqualError(t, err, "preparing network access to PureVPN: test error")
	assert.Equal(t, 2, revertCalls)

	// The fourth fetch has nothing to remove.
	_, err = fetcher.fetch(context.Background(), vpnSettings, nil, NewMockLogger(ctrl))
	require.EqualError(t, err, "preparing network access to PureVPN: test error")
	assert.Equal(t, 2, revertCalls)
	assert.Equal(t, 4, cleanupCalls)
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

// preTunnelMarkMatcher matches a mark which is not a reserved mark.
type preTunnelMarkMatcher struct{}

func (preTunnelMarkMatcher) Matches(x any) bool {
	mark, ok := x.(uint32)
	return ok && mark != 0 && mark != 0x567 && mark != 4545 && mark != 51820
}

func (preTunnelMarkMatcher) String() string {
	return "is a non reserved mark"
}

func Test_newWireguardFetcher(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	matcher := preTunnelMarkMatcher{}
	assert.True(t, matcher.Matches(uint32(0x7075)))
	assert.False(t, matcher.Matches(uint32(0x567)))
	assert.False(t, matcher.Matches(0x7075))
	assert.Equal(t, "is a non reserved mark", matcher.String())

	fetcher := newWireguardFetcher()

	assert.Equal(t, "/gluetun/purevpn-wireguard.json", fetcher.statePath)
	assert.WithinDuration(t, time.Now(), fetcher.timeNow(), time.Minute)

	// The HTTP client constructor opens the firewall for the default
	// DNS over HTTPS servers, with a random mark.
	var dohAddrPorts []netip.AddrPort
	for _, server := range defaultPreTunnelSettings().dohServers {
		for _, ip := range server.ips {
			dohAddrPorts = append(dohAddrPorts, netip.AddrPortFrom(ip, 443))
		}
	}
	ctx := context.Background()
	firewall := NewMockFirewall(ctrl)
	firewall.EXPECT().AllowOutputTemporarily(ctx, "tcp", matcher, dohAddrPorts).
		Return(func(context.Context) error { return nil }, errors.New("test error"))

	client, resolve, cleanup, err := fetcher.newHTTPClient(ctx, firewall, NewMockLogger(ctrl))

	assert.EqualError(t, err, "allowing DNS over HTTPS traffic: test error")
	assert.Nil(t, client)
	assert.Nil(t, resolve)
	assert.Empty(t, cleanup())
}
