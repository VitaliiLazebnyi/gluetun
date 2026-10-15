package wgapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testUsername    = "user@example.com"
	testPassword    = "correct-password"
	testTOTPSecret  = "JBSWY3DPEHPK3PXP" //nolint:gosec // test value
	testSSOCookie   = "valid-sso-session"
	testVPNUsername = "purevpn0s1234567"
	testSubsID      = "subs-123"
	testServerKey   = "Y0QnWR6mhgxOjNkPUkRdPYKYrB+pERhKFAuhkBapHw8="
	testClientKey   = "cGlwZXJzLXB1YmxpYy1rZXktZm9yLXRlc3RzLTAwMDA="
)

// fakePureVPN emulates the FusionAuth login and the member area API.
type fakePureVPN struct {
	t           *testing.T
	twoFactor   bool
	cloudflare  bool
	rejectToken string // API rejects this access token once

	mutex          sync.Mutex
	passwordLogins int
	tokenCount     int
	validTokens    map[string]bool
}

func newFakePureVPN(t *testing.T) *fakePureVPN {
	t.Helper()
	return &fakePureVPN{t: t, validTokens: map[string]bool{}}
}

func makeJWT(expiry time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString(
		[]byte(fmt.Sprintf(`{"exp":%d}`, expiry.Unix())))
	return header + "." + payload + ".signature"
}

const loginPage = `<html><body>
<form action="/oauth2/authorize" method="post">
<input type="hidden" name="captcha_token" value="">
<input type="hidden" name="client_id" value="` + clientID + `">
<input type="hidden" name="tenantId" value="` + tenantID + `">
<input type="hidden" name="redirect_uri" value="%s/v2/api/fusionauth/login">
<input type="hidden" name="response_type" value="code">
<input type="hidden" name="timezone" value="">
<input id="loginId" name="loginId" type="text">
<input id="password" name="password" type="password">
%s
<button type="submit">Login</button>
</form></body></html>`

const twoFactorPage = `<html><body>
<form action="/oauth2/two-factor" method="post">
<input type="hidden" name="twoFactorId" value="tf-1">
<input type="hidden" name="client_id" value="` + clientID + `">
<input id="code" name="code" type="text">
<input id="trustComputer" name="trustComputer" type="checkbox" value="true">
%s
</form></body></html>`

func (f *fakePureVPN) issueToken(w http.ResponseWriter, r *http.Request) {
	f.tokenCount++
	token := makeJWT(time.Now().Add(time.Hour)) + fmt.Sprint(f.tokenCount)
	f.validTokens[token] = true
	http.SetCookie(w, &http.Cookie{Name: "fusionauth.sso", Value: testSSOCookie, Path: "/"})
	http.Redirect(w, r, "/v2/api/fusionauth/login?code=abc", http.StatusFound)
}

func (f *fakePureVPN) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	if f.cloudflare {
		w.Header().Set("Server", "cloudflare")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "<html><title>Just a moment...</title></html>")
		return
	}

	baseURL := "http://" + r.Host
	switch r.Method + " " + r.URL.Path {
	case "GET /oauth2/authorize":
		cookie, err := r.Cookie("fusionauth.sso")
		if err == nil && cookie.Value == testSSOCookie {
			f.issueToken(w, r)
			return
		}
		fmt.Fprintf(w, loginPage, baseURL, "") //nolint:gosec // test server
	case "POST /oauth2/authorize":
		f.parseForm(r)
		assert.Equal(f.t, clientID, r.PostForm.Get("client_id"))
		f.passwordLogins++
		if r.PostForm.Get("loginId") != testUsername || r.PostForm.Get("password") != testPassword {
			fmt.Fprintf(w, loginPage, baseURL, //nolint:gosec // test server
				`<span class="error">Invalid login credentials.</span>`)
			return
		}
		if f.twoFactor {
			fmt.Fprintf(w, twoFactorPage, "")
			return
		}
		f.issueToken(w, r)
	case "POST /oauth2/two-factor":
		f.parseForm(r)
		assert.Equal(f.t, "tf-1", r.PostForm.Get("twoFactorId"))
		valid := totp.Validate(r.PostForm.Get("code"), testTOTPSecret)
		if !valid {
			fmt.Fprintf(w, twoFactorPage, `<div class="error">Invalid code</div>`)
			return
		}
		f.issueToken(w, r)
	case "GET /v2/api/fusionauth/login":
		token := ""
		for t := range f.validTokens {
			if strings.HasSuffix(t, fmt.Sprint(f.tokenCount)) {
				token = t
			}
		}
		http.SetCookie(w, &http.Cookie{Name: accessToken, Value: token, Path: "/"})
		http.Redirect(w, r, "/v2/dashboard", http.StatusFound)
	case "GET /v2/dashboard":
		fmt.Fprint(w, "<html>dashboard</html>")
	default:
		f.serveAPI(w, r)
	}
}

func (f *fakePureVPN) serveAPI(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == f.rejectToken || !f.validTokens[token] {
		f.rejectToken = ""
		delete(f.validTokens, token)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.parseForm(r)

	var body any
	switch r.URL.Path {
	case "/v2/api/subscription":
		body = []subscription{
			{ID: "expired", State: "expired", VPNUsernames: []string{"purevpn0sexpired"}},
			{ID: testSubsID, State: "active", VPNUsernames: []string{testVPNUsername}},
		}
	case "/v2/api/wireguard/get-encrypt-password":
		assert.Equal(f.t, testVPNUsername, r.PostForm.Get("username"))
		body = map[string]string{"encrypPass": "encrypted"}
	case "/v2/api/wireguard/get-wg-server":
		assert.Equal(f.t, testVPNUsername, r.PostForm.Get("sUsername"))
		assert.Equal(f.t, "encrypted", r.PostForm.Get("sPassword"))
		assert.Equal(f.t, "US", r.PostForm.Get("sCountrySlug"))
		assert.Equal(f.t, "8778", r.PostForm.Get("iCityId"))
		assert.Equal(f.t, testSubsID, r.PostForm.Get("sSubsId"))
		assert.Equal(f.t, testClientKey, r.PostForm.Get("sClientPublicKey"))
		body = []map[string]string{{
			"protocol_ip": "203.0.113.7",
			"wireguard_configuration": "[Interface]\nPrivateKey={clientPrivateKey}\n" +
				"Address=172.21.7.9\nDNS=103.109.1.1,103.109.1.2\n[Peer]\n" +
				"PublicKey=" + testServerKey + "\nAllowedIPs=0.0.0.0/0\n" +
				"Endpoint=us-ny.purevpn.net:51820\nPersistentKeepalive=21\n",
		}}
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	bodyJSON, err := json.Marshal(body)
	require.NoError(f.t, err)
	err = json.NewEncoder(w).Encode(apiResponse{Status: true, Body: bodyJSON})
	require.NoError(f.t, err)
}

func newTestRequest() ServerRequest {
	return ServerRequest{
		CountryCode:     "us",
		CityID:          8778,
		ClientPublicKey: testClientKey,
	}
}

func (f *fakePureVPN) parseForm(r *http.Request) {
	const maxBodySize = 1 << 20
	r.Body = http.MaxBytesReader(nil, r.Body, maxBodySize)
	require.NoError(f.t, r.ParseForm())
}

func newTestClient(t *testing.T, serverURL string, credentials Credentials, session Session) *Client {
	t.Helper()
	client, err := New(&http.Client{Timeout: 5 * time.Second}, serverURL, serverURL, credentials, session)
	require.NoError(t, err)
	return client
}

func Test_Client_FetchConfig(t *testing.T) {
	t.Parallel()

	credentials := Credentials{Username: testUsername, Password: testPassword}
	expectedConfig := Config{
		Addresses:           []netip.Prefix{netip.MustParsePrefix("172.21.7.9/32")},
		DNS:                 []netip.Addr{netip.MustParseAddr("103.109.1.1"), netip.MustParseAddr("103.109.1.2")},
		ServerPublicKey:     testServerKey,
		EndpointHost:        "us-ny.purevpn.net",
		EndpointPort:        51820,
		PersistentKeepalive: 21 * time.Second,
		ProtocolIP:          "203.0.113.7",
	}

	t.Run("password_login", func(t *testing.T) {
		t.Parallel()
		fake := newFakePureVPN(t)
		server := httptest.NewServer(fake)
		defer server.Close()

		client := newTestClient(t, server.URL, credentials, Session{})
		config, err := client.FetchConfig(context.Background(), newTestRequest())
		require.NoError(t, err)
		assert.Equal(t, expectedConfig, config)

		session := client.Session()
		assert.NotEmpty(t, session.AccessToken)
		assert.Equal(t, map[string]string{"fusionauth.sso": testSSOCookie}, session.AuthCookies)

		// Second fetch reuses the access token without logging in.
		_, err = client.FetchConfig(context.Background(), newTestRequest())
		require.NoError(t, err)
		assert.Equal(t, 1, fake.passwordLogins)
	})

	t.Run("invalid_credentials", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(newFakePureVPN(t))
		defer server.Close()

		client := newTestClient(t, server.URL,
			Credentials{Username: testUsername, Password: "wrong"}, Session{})
		_, err := client.FetchConfig(context.Background(), newTestRequest())
		require.ErrorIs(t, err, errInvalidCredentials)
		assert.ErrorContains(t, err, "Invalid login credentials.")
		assert.True(t, IsAuthError(err))
	})

	t.Run("credentials_not_set", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(newFakePureVPN(t))
		defer server.Close()

		client := newTestClient(t, server.URL, Credentials{}, Session{})
		_, err := client.FetchConfig(context.Background(), newTestRequest())
		require.ErrorIs(t, err, errCredentialsNotSet)
	})

	t.Run("two_factor_required_without_secret", func(t *testing.T) {
		t.Parallel()
		fake := newFakePureVPN(t)
		fake.twoFactor = true
		server := httptest.NewServer(fake)
		defer server.Close()

		client := newTestClient(t, server.URL, credentials, Session{})
		_, err := client.FetchConfig(context.Background(), newTestRequest())
		require.ErrorIs(t, err, errTwoFactorRequired)
	})

	t.Run("two_factor_with_valid_secret", func(t *testing.T) {
		t.Parallel()
		fake := newFakePureVPN(t)
		fake.twoFactor = true
		server := httptest.NewServer(fake)
		defer server.Close()

		withTOTP := credentials
		withTOTP.TOTPSecret = strings.ToLower(testTOTPSecret)
		client := newTestClient(t, server.URL, withTOTP, Session{})
		config, err := client.FetchConfig(context.Background(), newTestRequest())
		require.NoError(t, err)
		assert.Equal(t, expectedConfig, config)
	})

	t.Run("two_factor_with_wrong_secret", func(t *testing.T) {
		t.Parallel()
		fake := newFakePureVPN(t)
		fake.twoFactor = true
		server := httptest.NewServer(fake)
		defer server.Close()

		withTOTP := credentials
		withTOTP.TOTPSecret = "GEZDGNBVGY3TQOJQ"
		client := newTestClient(t, server.URL, withTOTP, Session{})
		_, err := client.FetchConfig(context.Background(), newTestRequest())
		require.ErrorIs(t, err, errTwoFactorCodeInvalid)
	})

	t.Run("stored_session_without_credentials", func(t *testing.T) {
		t.Parallel()
		fake := newFakePureVPN(t)
		fake.twoFactor = true // must not matter with a valid SSO session
		server := httptest.NewServer(fake)
		defer server.Close()

		session := Session{AuthCookies: map[string]string{"fusionauth.sso": testSSOCookie}}
		client := newTestClient(t, server.URL, Credentials{}, session)
		config, err := client.FetchConfig(context.Background(), newTestRequest())
		require.NoError(t, err)
		assert.Equal(t, expectedConfig, config)
		assert.Equal(t, 0, fake.passwordLogins)
	})

	t.Run("expired_stored_session_falls_back_on_credentials", func(t *testing.T) {
		t.Parallel()
		fake := newFakePureVPN(t)
		server := httptest.NewServer(fake)
		defer server.Close()

		session := Session{
			AccessToken: makeJWT(time.Now().Add(-time.Hour)),
			AuthCookies: map[string]string{"fusionauth.sso": "expired"},
		}
		client := newTestClient(t, server.URL, credentials, session)
		_, err := client.FetchConfig(context.Background(), newTestRequest())
		require.NoError(t, err)
		assert.Equal(t, 1, fake.passwordLogins)
	})

	t.Run("expired_stored_session_without_credentials", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(newFakePureVPN(t))
		defer server.Close()

		session := Session{AuthCookies: map[string]string{"fusionauth.sso": "expired"}}
		client := newTestClient(t, server.URL, Credentials{}, session)
		_, err := client.FetchConfig(context.Background(), newTestRequest())
		require.ErrorIs(t, err, errSessionExpired)
		require.ErrorIs(t, err, errCredentialsNotSet)
	})

	t.Run("rejected_access_token_triggers_login", func(t *testing.T) {
		t.Parallel()
		fake := newFakePureVPN(t)
		server := httptest.NewServer(fake)
		defer server.Close()

		// The token looks valid locally but the API rejects it.
		session := Session{AccessToken: makeJWT(time.Now().Add(time.Hour))}
		client := newTestClient(t, server.URL, credentials, session)
		config, err := client.FetchConfig(context.Background(), newTestRequest())
		require.NoError(t, err)
		assert.Equal(t, expectedConfig, config)
		assert.Equal(t, 1, fake.passwordLogins)
	})

	t.Run("cloudflare_block", func(t *testing.T) {
		t.Parallel()
		fake := newFakePureVPN(t)
		fake.cloudflare = true
		server := httptest.NewServer(fake)
		defer server.Close()

		client := newTestClient(t, server.URL, credentials, Session{})
		_, err := client.FetchConfig(context.Background(), newTestRequest())
		require.ErrorIs(t, err, errBlocked)
		assert.False(t, IsAuthError(err))
	})

	t.Run("network_error", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewServer(newFakePureVPN(t))
		serverURL := server.URL
		server.Close()

		client := newTestClient(t, serverURL, credentials, Session{})
		_, err := client.FetchConfig(context.Background(), newTestRequest())
		require.Error(t, err)
		assert.ErrorContains(t, err, "connection refused")
		assert.False(t, IsAuthError(err))
	})
}

func Test_selectSubscription_notFound(t *testing.T) {
	t.Parallel()
	fake := newFakePureVPN(t)
	server := httptest.NewServer(fake)
	defer server.Close()

	client := newTestClient(t, server.URL,
		Credentials{Username: testUsername, Password: testPassword}, Session{})
	request := newTestRequest()
	request.VPNUsername = "purevpn0sother"
	_, err := client.FetchConfig(context.Background(), request)
	require.ErrorIs(t, err, errSubscriptionNotFound)
	assert.ErrorContains(t, err, testVPNUsername)
}

func Test_accessTokenValid(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_000_000, 0)
	assert.False(t, accessTokenValid("", now))
	assert.True(t, accessTokenValid("opaque-token", now))
	assert.True(t, accessTokenValid(makeJWT(now.Add(time.Hour)), now))
	assert.False(t, accessTokenValid(makeJWT(now.Add(30*time.Second)), now))
	assert.False(t, accessTokenValid(makeJWT(now.Add(-time.Hour)), now))
}
