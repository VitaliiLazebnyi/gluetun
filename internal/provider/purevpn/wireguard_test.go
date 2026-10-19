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
	"slices"
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

// testSSOCookie is the fusionauth.sso single sign-on cookie value
// accepted by the fake API.
const testSSOCookie = "sso-cookie-value"

// fakeAPI serves the single sign-on login and the member area API
// endpoints, accepting only the testSSOCookie single sign-on cookie
// and the access token given, and records the client public keys.
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

func (f *fakeAPI) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	f.mutex.Lock()
	f.requests++
	f.mutex.Unlock()
	if request.URL.Path == "/oauth2/authorize" {
		cookie, err := request.Cookie("fusionauth.sso")
		if err == nil && cookie.Value == testSSOCookie {
			// Logged in through the single sign-on session.
			http.SetCookie(writer, &http.Cookie{Name: "fa_token", Value: f.token, Path: "/"}) //nolint:gosec
			_, _ = writer.Write([]byte("<html>dashboard</html>"))
			return
		}
	}
	if request.Header.Get("Authorization") != "Bearer "+f.token {
		// Not logged in: show the login page, as the auth server would.
		writer.Header().Set("Content-Type", "text/html")
		page := `<form action="/oauth2/authorize" method="post">` +
			`<input name="loginId"><input name="password"></form>`
		if f.loginError != "" {
			page += `<div class="error">` + f.loginError + `</div>`
		}
		_, _ = writer.Write([]byte(page))
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 1<<20)
	_ = request.ParseForm()
	var body string
	switch request.URL.Path {
	case "/v2/api/subscription":
		body = `[{"id":"s1","state":"active","vpnusernames":["purevpn0s1"]}]`
	case "/v2/api/wireguard/get-encrypt-password":
		body = `{"encrypPass":"x"}`
	case "/v2/api/wireguard/get-wg-server":
		f.mutex.Lock()
		f.clientPubKey = request.PostForm.Get("sClientPublicKey")
		f.mutex.Unlock()
		config := "[Interface]\nAddress=172.21.7.9\n[Peer]\nPublicKey=" + testServerPublicKey +
			"\nEndpoint=" + f.endpoint + "\nPersistentKeepalive=21\n"
		configJSON, err := json.Marshal(config)
		if err != nil {
			panic(err)
		}
		body = `[{"wireguard_configuration":` + string(configJSON) + `}]`
	default:
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	_, _ = writer.Write([]byte(`{"status":true,"body":` + body + `}`))
}

// newTestServer returns a test HTTPS server for the API given,
// and a restricted network reaching it.
func newTestServer(t *testing.T, api *fakeAPI) (server *httptest.Server, network *fakeNetwork) {
	t.Helper()
	server = httptest.NewTLSServer(api)
	t.Cleanup(server.Close)
	return server, newFakeNetwork(server)
}

func newTestFetcher(t *testing.T, serverURL string, network RestrictedNetwork) *wireguardFetcher {
	t.Helper()
	return &wireguardFetcher{
		network:   network,
		statePath: filepath.Join(t.TempDir(), "state", "purevpn.json"),
		authURL:   serverURL,
		appURL:    serverURL,
	}
}

func testVPNSettings(sessionToken, privateKey string) settings.VPN {
	return settings.VPN{
		Wireguard: settings.Wireguard{
			PrivateKey:                  new(privateKey),
			PersistentKeepaliveInterval: new(time.Duration(0)),
		},
		Provider: settings.Provider{
			ServerSelection: settings.ServerSelection{Countries: []string{"United States"}},
		},
		PureVPN: settings.PureVPN{
			Username:       new(""),
			Password:       new(""),
			TOTPSecret:     new(""),
			SessionToken:   new(sessionToken),
			CityID:         new(uint32(8778)),
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
		logger.EXPECT().Debug("using PureVPN session token as single sign-on cookie"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
		logger.EXPECT().Info("PureVPN Wireguard server us-ny.purevpn.net (198.51.100.9:51820)"),
	)
	fetcher := newTestFetcher(t, server.URL, network)
	connection, err := fetcher.fetch(context.Background(),
		testVPNSettings(testSSOCookie, ""), logger)
	require.NoError(t, err)

	_, ok := network.openCtx.Deadline()
	assert.True(t, ok, "requests must be bounded by a timeout")
	hostnames, cleanups := network.opened()
	requestsCount := int(api.requestsCount())
	assert.Greater(t, requestsCount, 1)
	assert.Equal(t, slices.Repeat([]string{strings.TrimPrefix(server.URL, "https://")}, requestsCount), hostnames,
		"each request must open its own connection")
	assert.Equal(t, slices.Repeat([]uint{1}, requestsCount), cleanups, "each connection must be cleaned up once")

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
	assert.Equal(t, hashHex(testSSOCookie), state.SessionTokenHash)
	assert.Equal(t, hashHex(""), state.UsernameHash)

	// A restarted fetcher reuses the persisted key pair and session,
	// even without the session token in the settings.
	restartedLogger := NewMockLogger(ctrl)
	gomock.InOrder(
		restartedLogger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
		restartedLogger.EXPECT().Info("PureVPN Wireguard server us-ny.purevpn.net (198.51.100.9:51820)"),
	)
	restarted := newTestFetcher(t, server.URL, network)
	restarted.statePath = fetcher.statePath
	second, err := restarted.fetch(context.Background(),
		testVPNSettings("", ""), restartedLogger)
	require.NoError(t, err)
	assert.Equal(t, connection.PrivateKey, second.PrivateKey)
}

// Test_Provider_FetchWireguardConnection tests the provider entry point
// uses the restricted network given to New, and the private key from
// the settings instead of generating one.
func Test_Provider_FetchWireguardConnection(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	api := &fakeAPI{token: testJWT, endpoint: "203.0.113.5:51820"}
	server, network := newTestServer(t, api)

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	logger := NewMockWireguardLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Debug("using PureVPN session token as single sign-on cookie"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
		logger.EXPECT().Info("PureVPN Wireguard server 203.0.113.5 (203.0.113.5:51820)"),
	)
	provider := New(nil, nil, nil, nil, nil, network)
	provider.wireguard.statePath = filepath.Join(t.TempDir(), "purevpn.json")
	provider.wireguard.authURL = server.URL
	provider.wireguard.appURL = server.URL

	connection, err := provider.FetchWireguardConnection(context.Background(),
		testVPNSettings(testSSOCookie, key.String()), logger)

	require.NoError(t, err)
	hostnames, _ := network.opened()
	assert.Len(t, hostnames, int(api.requestsCount()), "the restricted network given to New must be used")
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
		logger.EXPECT().Debug("using PureVPN session token as single sign-on cookie"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
	)
	fetcher := newTestFetcher(t, server.URL, network)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fetcher.fetch(ctx, testVPNSettings(testSSOCookie, ""), logger)
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, api.requestsCount())
}

func Test_wireguardFetcher_fetch_authError(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	api := &fakeAPI{token: testJWT, endpoint: "203.0.113.5:51820"}
	server, network := newTestServer(t, api)

	fetcher := newTestFetcher(t, server.URL, network)

	// No credentials and a rejected token: the login page is shown.
	logger := NewMockLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Info("generated a new Wireguard key pair for PureVPN"),
		logger.EXPECT().Debug("using PureVPN session token as single sign-on cookie"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
	)
	_, err := fetcher.fetch(context.Background(),
		testVPNSettings("rejected-token", ""), logger)
	require.ErrorContains(t, err, "requesting configuration from PureVPN: ")
	assert.ErrorContains(t, err, "PureVPN account username and password are not set")
	requestsAfterFirstFetch := api.requestsCount()
	require.NotZero(t, requestsAfterFirstFetch)

	// Same settings: PureVPN is contacted again, the VPN loop
	// taking care of waiting between connection attempts.
	logger = NewMockLogger(ctrl)
	logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778")
	_, err = fetcher.fetch(context.Background(),
		testVPNSettings("rejected-token", ""), logger)
	require.ErrorContains(t, err, "PureVPN account username and password are not set")
	requestsAfterSecondFetch := api.requestsCount()
	assert.Greater(t, requestsAfterSecondFetch, requestsAfterFirstFetch)

	// Changed session token: it replaces the stored session.
	logger = NewMockLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Debug("using PureVPN session token as single sign-on cookie"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
		logger.EXPECT().Info("PureVPN Wireguard server 203.0.113.5 (203.0.113.5:51820)"),
	)
	_, err = fetcher.fetch(context.Background(),
		testVPNSettings(testSSOCookie, ""), logger)
	require.NoError(t, err)
	assert.Greater(t, api.requestsCount(), requestsAfterSecondFetch)
}

func Test_wireguardFetcher_fetch_cleanupError(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	api := &fakeAPI{token: testJWT, endpoint: "203.0.113.5:51820"}
	server, network := newTestServer(t, api)
	// For example the firewall got disabled during the fetch,
	// so removing the firewall rule fails.
	network.cleanupErrs = map[uint]error{0: errors.New("test error")}

	logger := NewMockLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Info("generated a new Wireguard key pair for PureVPN"),
		logger.EXPECT().Debug("using PureVPN session token as single sign-on cookie"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
		logger.EXPECT().Info("PureVPN Wireguard server 203.0.113.5 (203.0.113.5:51820)"),
		logger.EXPECT().Warn("cleaning up connections to PureVPN: cleanup 0: test error"),
	)
	fetcher := newTestFetcher(t, server.URL, network)

	_, err := fetcher.fetch(context.Background(), testVPNSettings(testSSOCookie, ""), logger)

	assert.NoError(t, err)
}

func Test_wireguardFetcher_applyAccount(t *testing.T) {
	t.Parallel()

	const discardedMessage = "discarding the stored PureVPN session since it is not for the configured account"
	const seededMessage = "using PureVPN session token as single sign-on cookie"
	storedSession := wgapi.Session{
		AccessToken: "stored-access-token",
		AuthCookies: map[string]string{"fusionauth.sso": "stored-sso", "fusionauth.trust": "trusted"},
	}

	testCases := map[string]struct {
		initialState wireguardState
		username     string
		token        string
		info         string
		debug        string
		state        wireguardState
	}{
		"new_state_without_token": {
			username: "alice",
			state:    wireguardState{UsernameHash: hashHex("alice")},
		},
		"new_state_with_token": {
			username: "alice",
			token:    "new-sso",
			debug:    seededMessage,
			state: wireguardState{
				Session:          wgapi.Session{AuthCookies: map[string]string{"fusionauth.sso": "new-sso"}},
				UsernameHash:     hashHex("alice"),
				SessionTokenHash: hashHex("new-sso"),
			},
		},
		"unchanged_account_without_token": {
			initialState: wireguardState{
				PrivateKey:   "key",
				Session:      storedSession,
				UsernameHash: hashHex("alice"),
			},
			username: "alice",
			state: wireguardState{
				PrivateKey:   "key",
				Session:      storedSession,
				UsernameHash: hashHex("alice"),
			},
		},
		"unchanged_account_and_token": {
			initialState: wireguardState{
				PrivateKey:       "key",
				Session:          storedSession,
				UsernameHash:     hashHex("alice"),
				SessionTokenHash: hashHex("old-sso"),
			},
			username: "alice",
			token:    "old-sso",
			state: wireguardState{
				PrivateKey:       "key",
				Session:          storedSession,
				UsernameHash:     hashHex("alice"),
				SessionTokenHash: hashHex("old-sso"),
			},
		},
		"token_removed": {
			initialState: wireguardState{
				PrivateKey:       "key",
				Session:          storedSession,
				UsernameHash:     hashHex("alice"),
				SessionTokenHash: hashHex("old-sso"),
			},
			username: "alice",
			state: wireguardState{
				PrivateKey:       "key",
				Session:          storedSession,
				UsernameHash:     hashHex("alice"),
				SessionTokenHash: hashHex("old-sso"),
			},
		},
		"changed_token_keeps_other_cookies": {
			initialState: wireguardState{
				PrivateKey:       "key",
				Session:          storedSession,
				UsernameHash:     hashHex("alice"),
				SessionTokenHash: hashHex("old-sso"),
			},
			username: "alice",
			token:    "new-sso",
			debug:    seededMessage,
			state: wireguardState{
				PrivateKey: "key",
				Session: wgapi.Session{
					AuthCookies: map[string]string{"fusionauth.sso": "new-sso", "fusionauth.trust": "trusted"},
				},
				UsernameHash:     hashHex("alice"),
				SessionTokenHash: hashHex("new-sso"),
			},
		},
		"changed_username_discards_session": {
			initialState: wireguardState{
				PrivateKey:       "key",
				Session:          storedSession,
				UsernameHash:     hashHex("alice"),
				SessionTokenHash: hashHex("old-sso"),
			},
			username: "bob",
			info:     discardedMessage,
			state: wireguardState{
				PrivateKey:   "key",
				UsernameHash: hashHex("bob"),
			},
		},
		"changed_username_with_same_token": {
			initialState: wireguardState{
				PrivateKey:       "key",
				Session:          storedSession,
				UsernameHash:     hashHex("alice"),
				SessionTokenHash: hashHex("old-sso"),
			},
			username: "bob",
			token:    "old-sso",
			info:     discardedMessage,
			debug:    seededMessage,
			state: wireguardState{
				PrivateKey:       "key",
				Session:          wgapi.Session{AuthCookies: map[string]string{"fusionauth.sso": "old-sso"}},
				UsernameHash:     hashHex("bob"),
				SessionTokenHash: hashHex("old-sso"),
			},
		},
		"missing_username_hash_discards_session": {
			initialState: wireguardState{
				PrivateKey:       "key",
				Session:          storedSession,
				SessionTokenHash: hashHex("old-sso"),
			},
			username: "alice",
			token:    "old-sso",
			info:     discardedMessage,
			debug:    seededMessage,
			state: wireguardState{
				PrivateKey:       "key",
				Session:          wgapi.Session{AuthCookies: map[string]string{"fusionauth.sso": "old-sso"}},
				UsernameHash:     hashHex("alice"),
				SessionTokenHash: hashHex("old-sso"),
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			logger := NewMockLogger(ctrl)
			if testCase.info != "" {
				logger.EXPECT().Info(testCase.info)
			}
			if testCase.debug != "" {
				logger.EXPECT().Debug(testCase.debug)
			}
			fetcher := &wireguardFetcher{state: testCase.initialState}

			fetcher.applyAccount(testCase.username, testCase.token, logger)
			assert.Equal(t, testCase.state, fetcher.state)

			// A refreshed session is kept for the same settings.
			fetcher.state.Session = wgapi.Session{AccessToken: "refreshed"}
			fetcher.applyAccount(testCase.username, testCase.token, logger)
			assert.Equal(t, wgapi.Session{AccessToken: "refreshed"}, fetcher.state.Session)
		})
	}
}

func Test_wireguardFetcher_fetch_accountChange(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	api := &fakeAPI{token: testJWT, endpoint: "203.0.113.5:51820"}
	server, network := newTestServer(t, api)
	fetcher := newTestFetcher(t, server.URL, network)

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	fetcher.state.PrivateKey = key.String()

	// Logged in for the first account through the session token.
	logger := NewMockLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Debug("using PureVPN session token as single sign-on cookie"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
		logger.EXPECT().Info("PureVPN Wireguard server 203.0.113.5 (203.0.113.5:51820)"),
	)
	vpnSettings := testVPNSettings(testSSOCookie, "")
	*vpnSettings.PureVPN.Username = "alice"
	*vpnSettings.PureVPN.Password = "alice-password"
	_, err = fetcher.fetch(context.Background(), vpnSettings, logger)
	require.NoError(t, err)

	// Password changed for the same account: the stored session is used.
	logger = NewMockLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
		logger.EXPECT().Info("PureVPN Wireguard server 203.0.113.5 (203.0.113.5:51820)"),
	)
	vpnSettings = testVPNSettings("", "")
	*vpnSettings.PureVPN.Username = "alice"
	*vpnSettings.PureVPN.Password = "alice-new-password"
	_, err = fetcher.fetch(context.Background(), vpnSettings, logger)
	require.NoError(t, err)

	// Another account: the stored session of the first account must not
	// be used, and the login with the new account credentials fails.
	logger = NewMockLogger(ctrl)
	gomock.InOrder(
		logger.EXPECT().Info("discarding the stored PureVPN session since it is not for the configured account"),
		logger.EXPECT().Info("fetching Wireguard configuration from PureVPN for country US city ID 8778"),
	)
	vpnSettings = testVPNSettings("", "")
	*vpnSettings.PureVPN.Username = "bob"
	*vpnSettings.PureVPN.Password = "bob-password"
	_, err = fetcher.fetch(context.Background(), vpnSettings, logger)
	require.ErrorContains(t, err, "requesting configuration from PureVPN: ")

	data, err := os.ReadFile(fetcher.statePath)
	require.NoError(t, err)
	var state wireguardState
	require.NoError(t, json.Unmarshal(data, &state))
	assert.Equal(t, key.String(), state.PrivateKey, "the key pair must be kept")
	assert.Equal(t, hashHex("bob"), state.UsernameHash)
	assert.Empty(t, state.SessionTokenHash)
	assert.NotEqual(t, testJWT, state.Session.AccessToken)
	assert.NotContains(t, state.Session.AuthCookies, "fusionauth.sso")
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
				logger.EXPECT().Debug("using PureVPN session token as single sign-on cookie")
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
					logger.EXPECT().Debug("using PureVPN session token as single sign-on cookie"),
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
					logger.EXPECT().Debug("using PureVPN session token as single sign-on cookie"),
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
					logger.EXPECT().Debug("using PureVPN session token as single sign-on cookie"),
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
					logger.EXPECT().Debug("using PureVPN session token as single sign-on cookie"),
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
			network.openErrs = map[uint]error{0: testCase.openErr}

			fetcher := newTestFetcher(t, server.URL, network)
			if testCase.modifyFetcher != nil {
				testCase.modifyFetcher(fetcher)
			}
			vpnSettings := testVPNSettings(testSSOCookie, testCase.privateKey)
			*vpnSettings.PureVPN.CityID = 0

			connection, err := fetcher.fetch(context.Background(), vpnSettings, testCase.makeLogger(ctrl))

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
