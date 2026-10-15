package wgapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testUsername = "user@example.com"

const testPassword = "correct-password"

const testTOTPSecret = "JBSWY3DPEHPK3PXP" //nolint:gosec // test value

const testSSOCookie = "valid-sso-session"

const testVPNUsername = "purevpn0s1234567"

const testSubsID = "subs-123"

const testServerKey = "Y0QnWR6mhgxOjNkPUkRdPYKYrB+pERhKFAuhkBapHw8="

const testClientKey = "cGlwZXJzLXB1YmxpYy1rZXktZm9yLXRlc3RzLTAwMDA="

// fakePureVPN emulates the FusionAuth login and the member area API.
// Its fields must only be accessed with the mutex locked once the
// test server is started.
type fakePureVPN struct {
	t *testing.T

	mutex sync.Mutex
	// Settings
	twoFactor                   bool
	twoFactorMethods            string // HTML radio inputs to show a method selection page
	cloudflare                  bool
	captcha                     bool
	subscriptionEndpointMissing bool
	subscriptions               []subscription
	singleServerObject          bool
	brokenAuthorizePages        uint   // number of GET authorize pages without any form
	htmlAPIResponses            uint   // number of API responses with an HTML page
	rejectToken                 string // API rejects this access token once
	ssoDisabled                 bool   // ignore the single sign-on cookie
	// State
	counters    fakeCounters
	latestToken string
	validTokens map[string]bool
}

type fakeCounters struct {
	passwordLogins  uint
	twoFactorLogins uint
	tokens          uint
}

func newFakePureVPN(t *testing.T) *fakePureVPN {
	t.Helper()
	return &fakePureVPN{t: t, validTokens: map[string]bool{}}
}

func (f *fakePureVPN) getCounters() fakeCounters {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.counters
}

func makeJWT(expiry time.Time, tokenID uint) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString(
		fmt.Appendf(nil, `{"exp":%d,"jti":"%d"}`, expiry.Unix(), tokenID))
	return header + "." + payload + ".signature"
}

// loginPage has hidden captcha messages which must be ignored.
const loginPage = `<html><body>
<template><div class="error">Please complete the captcha</div></template>
<div class="error" style="display: none">Captcha verification failed</div>
<form action="/oauth2/authorize" method="post">
<input type="hidden" name="captcha_token" value="">
<input type="hidden" name="client_id" value="` + clientID + `">
<input type="hidden" name="tenantId" value="9707f41e-21a4-bbc5-dcbc-fdf6b61cc68f">
<input type="hidden" name="redirect_uri" value="%s/v2/api/fusionauth/login">
<input type="hidden" name="response_type" value="code">
<input type="hidden" name="timezone" value="">
<div class="form-row%s">
<input id="loginId" name="loginId" type="text">
<input id="password" name="password" type="password">
%s
</div>
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

const twoFactorMethodsPage = `<html><body>
<form action="/oauth2/two-factor-methods" method="post">
<input type="hidden" name="twoFactorId" value="tf-1">
%s
<button type="submit">Continue</button>
</form></body></html>`

const emailMethod = `<label class="radio"><input type="radio" name="methodId" value="m-email" checked>
<span>Email to u***@example.com</span></label>`

const smsMethod = `<label class="radio"><input type="radio" name="methodId" value="m-sms"> SMS</label>`

const authenticatorMethod = `<input type="radio" id="method-auth" name="methodId" value="m-auth">
<label for="method-auth">Authenticator app</label>`

func (f *fakePureVPN) issueToken(w http.ResponseWriter, r *http.Request) {
	f.counters.tokens++
	f.latestToken = makeJWT(time.Now().Add(time.Hour), f.counters.tokens)
	f.validTokens[f.latestToken] = true
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
		f.serveAuthorizePage(w, r, baseURL)
	case "POST /oauth2/authorize":
		if !f.parseForm(w, r) {
			return
		}
		assert.Equal(f.t, clientID, r.PostForm.Get("client_id"))
		f.counters.passwordLogins++
		switch {
		case f.captcha:
			fmt.Fprintf(w, loginPage, baseURL, " error", //nolint:gosec // test server
				`<span class="error">Please complete the captcha.</span>`)
		case r.PostForm.Get("loginId") != testUsername || r.PostForm.Get("password") != testPassword:
			fmt.Fprintf(w, loginPage, baseURL, " error", //nolint:gosec // test server
				`<span class="error">Invalid login credentials.</span>`)
		case f.twoFactor && f.twoFactorMethods != "":
			fmt.Fprintf(w, twoFactorMethodsPage, f.twoFactorMethods)
		case f.twoFactor:
			fmt.Fprintf(w, twoFactorPage, "")
		default:
			f.issueToken(w, r)
		}
	case "POST /oauth2/two-factor-methods":
		if !f.parseForm(w, r) {
			return
		}
		assert.Equal(f.t, "m-auth", r.PostForm.Get("methodId"))
		fmt.Fprintf(w, twoFactorPage, "")
	case "POST /oauth2/two-factor":
		if !f.parseForm(w, r) {
			return
		}
		f.counters.twoFactorLogins++
		assert.Equal(f.t, "tf-1", r.PostForm.Get("twoFactorId"))
		assert.Equal(f.t, "true", r.PostForm.Get("trustComputer"))
		if !totp.Validate(r.PostForm.Get("code"), testTOTPSecret) {
			fmt.Fprintf(w, twoFactorPage, `<div class="error">Invalid code</div>`)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "fusionauth.trust", Value: "trusted", Path: "/"})
		f.issueToken(w, r)
	case "GET /v2/api/fusionauth/login":
		http.SetCookie(w, &http.Cookie{Name: accessToken, Value: f.latestToken, Path: "/"})
		http.Redirect(w, r, "/v2/dashboard", http.StatusFound)
	case "GET /v2/dashboard":
		fmt.Fprint(w, "<html>dashboard</html>")
	default:
		f.serveAPI(w, r)
	}
}

func (f *fakePureVPN) serveAuthorizePage(w http.ResponseWriter, r *http.Request, baseURL string) {
	if f.brokenAuthorizePages > 0 {
		f.brokenAuthorizePages--
		fmt.Fprint(w, "<html>Under maintenance</html>")
		return
	}
	cookie, err := r.Cookie("fusionauth.sso")
	switch {
	case err != nil, f.ssoDisabled:
	case cookie.Value == testSSOCookie:
		f.issueToken(w, r)
		return
	case cookie.Value == "untrusted": // trusted device cookie expired
		fmt.Fprintf(w, twoFactorPage, "")
		return
	}
	fmt.Fprintf(w, loginPage, baseURL, "", "") //nolint:gosec // test server
}

func (f *fakePureVPN) serveAPI(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == f.rejectToken || !f.validTokens[token] {
		f.rejectToken = ""
		delete(f.validTokens, token)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if f.htmlAPIResponses > 0 {
		f.htmlAPIResponses--
		delete(f.validTokens, token)
		fmt.Fprint(w, "<html>login</html>")
		return
	}
	if !f.parseForm(w, r) {
		return
	}

	subscriptions := f.subscriptions
	if subscriptions == nil {
		subscriptions = []subscription{
			{ID: "expired", State: "expired", VPNUsernames: []string{"purevpn0sexpired"}},
			{ID: testSubsID, State: "active", VPNUsernames: []string{testVPNUsername}},
		}
	}

	var body any
	switch r.URL.Path {
	case "/v2/api/subscription":
		if f.subscriptionEndpointMissing {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body = subscriptions
	case "/v2/api/on-boarding":
		body = map[string]any{"subscriptions": subscriptions}
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
		server := map[string]string{
			"protocol_ip": "203.0.113.7",
			"wireguard_configuration": "[Interface]\nPrivateKey={clientPrivateKey}\n" +
				"Address=172.21.7.9\nDNS=103.109.1.1,103.109.1.2\n[Peer]\n" +
				"PublicKey=" + testServerKey + "\nAllowedIPs=0.0.0.0/0\n" +
				"Endpoint=us-ny.purevpn.net:51820\nPersistentKeepalive=21\n",
		}
		body = []map[string]string{server}
		if f.singleServerObject {
			body = server
		}
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	bodyJSON, err := json.Marshal(body)
	if !assert.NoError(f.t, err) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = json.NewEncoder(w).Encode(apiResponse{Status: true, Body: bodyJSON})
	assert.NoError(f.t, err)
}

func (f *fakePureVPN) parseForm(w http.ResponseWriter, r *http.Request) (ok bool) {
	const maxBodySize = 1 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	err := r.ParseForm()
	if !assert.NoError(f.t, err) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func newTestRequest() ServerRequest {
	return ServerRequest{
		CountryCode:     "us",
		CityID:          8778,
		ClientPublicKey: testClientKey,
	}
}

func newTestClient(t *testing.T, serverURL string, credentials Credentials, session Session) *Client {
	t.Helper()
	client, err := New(&http.Client{Timeout: 5 * time.Second}, serverURL, serverURL, credentials, session)
	require.NoError(t, err)
	return client
}

func newExpectedConfig() Config {
	return Config{
		Addresses:           []netip.Prefix{netip.MustParsePrefix("172.21.7.9/32")},
		DNS:                 []netip.Addr{netip.MustParseAddr("103.109.1.1"), netip.MustParseAddr("103.109.1.2")},
		ServerPublicKey:     testServerKey,
		EndpointHost:        "us-ny.purevpn.net",
		EndpointPort:        51820,
		PersistentKeepalive: 21 * time.Second,
		ProtocolIP:          "203.0.113.7",
	}
}

func Test_Client_FetchConfig(t *testing.T) {
	t.Parallel()

	credentials := Credentials{Username: testUsername, Password: testPassword}
	credentialsWithTOTP := Credentials{
		Username:   testUsername,
		Password:   testPassword,
		TOTPSecret: strings.ToLower(testTOTPSecret),
	}
	ssoCookies := map[string]string{"fusionauth.sso": testSSOCookie}
	trustedCookies := map[string]string{"fusionauth.sso": testSSOCookie, "fusionauth.trust": "trusted"}

	testCases := map[string]struct {
		setup       func(fake *fakePureVPN)
		credentials Credentials
		session     Session
		request     func(request *ServerRequest)
		errWrapped  error
		errMessage  string
		authError   bool
		authCookies map[string]string
		counters    fakeCounters
	}{
		"password_login": {
			credentials: credentials,
			authCookies: ssoCookies,
			counters:    fakeCounters{passwordLogins: 1, tokens: 1},
		},
		"invalid_credentials": {
			credentials: Credentials{Username: testUsername, Password: "wrong"},
			errWrapped:  errInvalidCredentials,
			errMessage:  "Invalid login credentials.",
			authError:   true,
			counters:    fakeCounters{passwordLogins: 1},
		},
		"captcha_required": {
			setup:       func(fake *fakePureVPN) { fake.captcha = true },
			credentials: credentials,
			errWrapped:  errCaptchaRequired,
			errMessage:  "Please complete the captcha.",
			authError:   true,
			counters:    fakeCounters{passwordLogins: 1},
		},
		"credentials_not_set": {
			errWrapped: errCredentialsNotSet,
			authError:  true,
		},
		"two_factor_required_without_secret": {
			setup:       func(fake *fakePureVPN) { fake.twoFactor = true },
			credentials: credentials,
			errWrapped:  errTwoFactorRequired,
			authError:   true,
			counters:    fakeCounters{passwordLogins: 1},
		},
		"two_factor_with_valid_secret": {
			setup:       func(fake *fakePureVPN) { fake.twoFactor = true },
			credentials: credentialsWithTOTP,
			authCookies: trustedCookies,
			counters:    fakeCounters{passwordLogins: 1, twoFactorLogins: 1, tokens: 1},
		},
		"two_factor_with_wrong_secret": {
			setup: func(fake *fakePureVPN) { fake.twoFactor = true },
			credentials: Credentials{ //nolint:gosec // test value
				Username: testUsername, Password: testPassword, TOTPSecret: "GEZDGNBVGY3TQOJQ",
			},
			errWrapped: errTwoFactorCodeInvalid,
			errMessage: "Invalid code",
			authError:  true,
			counters:   fakeCounters{passwordLogins: 1, twoFactorLogins: 1},
		},
		"two_factor_method_selection": {
			setup: func(fake *fakePureVPN) {
				fake.twoFactor = true
				fake.twoFactorMethods = emailMethod + authenticatorMethod
			},
			credentials: credentialsWithTOTP,
			authCookies: trustedCookies,
			counters:    fakeCounters{passwordLogins: 1, twoFactorLogins: 1, tokens: 1},
		},
		"two_factor_method_unsupported": {
			setup: func(fake *fakePureVPN) {
				fake.twoFactor = true
				fake.twoFactorMethods = emailMethod + smsMethod
			},
			credentials: credentialsWithTOTP,
			errWrapped:  errTwoFactorMethodUnsupported,
			authError:   true,
			counters:    fakeCounters{passwordLogins: 1},
		},
		"stored_session_without_credentials": {
			setup:       func(fake *fakePureVPN) { fake.twoFactor = true }, // must not matter
			session:     Session{AuthCookies: map[string]string{"fusionauth.sso": testSSOCookie}},
			authCookies: ssoCookies,
			counters:    fakeCounters{tokens: 1},
		},
		"expired_stored_session_falls_back_on_credentials": {
			credentials: credentials,
			session: Session{
				AccessToken: makeJWT(time.Now().Add(-time.Hour), 0),
				AuthCookies: map[string]string{"fusionauth.sso": "expired"},
			},
			authCookies: ssoCookies,
			counters:    fakeCounters{passwordLogins: 1, tokens: 1},
		},
		"expired_stored_session_without_credentials": {
			session:    Session{AuthCookies: map[string]string{"fusionauth.sso": "expired"}},
			errWrapped: errSessionExpired,
			errMessage: "PureVPN account username and password are not set",
			authError:  true,
		},
		"stored_session_with_expired_trusted_device": {
			setup:       func(fake *fakePureVPN) { fake.twoFactor = true },
			credentials: credentialsWithTOTP,
			session:     Session{AuthCookies: map[string]string{"fusionauth.sso": "untrusted"}},
			authCookies: trustedCookies,
			counters:    fakeCounters{twoFactorLogins: 1, tokens: 1},
		},
		"stored_session_unexpected_response_falls_back_on_credentials": {
			setup:       func(fake *fakePureVPN) { fake.brokenAuthorizePages = 1 },
			credentials: credentials,
			session:     Session{AuthCookies: map[string]string{"fusionauth.sso": "stale"}},
			authCookies: ssoCookies,
			counters:    fakeCounters{passwordLogins: 1, tokens: 1},
		},
		"stored_session_unexpected_response_without_credentials": {
			setup:      func(fake *fakePureVPN) { fake.brokenAuthorizePages = 1 },
			session:    Session{AuthCookies: map[string]string{"fusionauth.sso": "stale"}},
			errWrapped: errUnexpectedResponse,
			errMessage: "logging in with stored session",
		},
		"rejected_access_token_triggers_login": {
			credentials: credentials,
			// The token looks valid locally but the API rejects it.
			session:     Session{AccessToken: makeJWT(time.Now().Add(time.Hour), 0)},
			authCookies: ssoCookies,
			counters:    fakeCounters{passwordLogins: 1, tokens: 1},
		},
		"html_api_response_triggers_login": {
			setup:       func(fake *fakePureVPN) { fake.htmlAPIResponses = 1 },
			credentials: credentials,
			authCookies: ssoCookies,
			counters:    fakeCounters{passwordLogins: 1, tokens: 2},
		},
		"cloudflare_block": {
			setup:       func(fake *fakePureVPN) { fake.cloudflare = true },
			credentials: credentials,
			errWrapped:  errBlocked,
		},
		"on_boarding_fallback": {
			setup:       func(fake *fakePureVPN) { fake.subscriptionEndpointMissing = true },
			credentials: credentials,
			authCookies: ssoCookies,
			counters:    fakeCounters{passwordLogins: 1, tokens: 1},
		},
		"single_server_object": {
			setup:       func(fake *fakePureVPN) { fake.singleServerObject = true },
			credentials: credentials,
			authCookies: ssoCookies,
			counters:    fakeCounters{passwordLogins: 1, tokens: 1},
		},
		"no_active_subscription": {
			setup: func(fake *fakePureVPN) {
				fake.subscriptions = []subscription{{ID: "old", State: "expired", VPNUsernames: []string{"x"}}}
			},
			credentials: credentials,
			errWrapped:  errNoActiveSubscription,
			counters:    fakeCounters{passwordLogins: 1, tokens: 1},
		},
		"subscription_selected_by_id": {
			setup: func(fake *fakePureVPN) {
				fake.subscriptions = []subscription{
					{ID: "other", State: "active", VPNUsernames: []string{"purevpn0sother"}},
					{ID: testSubsID, State: "active", VPNUsernames: []string{testVPNUsername}},
				}
			},
			credentials: credentials,
			request:     func(request *ServerRequest) { request.SubscriptionID = testSubsID },
			authCookies: ssoCookies,
			counters:    fakeCounters{passwordLogins: 1, tokens: 1},
		},
		"subscription_not_found": {
			credentials: credentials,
			request:     func(request *ServerRequest) { request.VPNUsername = "purevpn0sother" },
			errWrapped:  errSubscriptionNotFound,
			errMessage:  testVPNUsername,
			counters:    fakeCounters{passwordLogins: 1, tokens: 1},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fake := newFakePureVPN(t)
			if testCase.setup != nil {
				testCase.setup(fake)
			}
			server := httptest.NewServer(fake)
			defer server.Close()

			client := newTestClient(t, server.URL, testCase.credentials, testCase.session)
			request := newTestRequest()
			if testCase.request != nil {
				testCase.request(&request)
			}
			config, err := client.FetchConfig(context.Background(), request)

			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			}
			assert.Equal(t, testCase.authError, IsAuthError(err))
			assert.Equal(t, testCase.counters, fake.getCounters())
			if testCase.errWrapped != nil {
				return
			}
			assert.Equal(t, newExpectedConfig(), config)
			session := client.Session()
			assert.True(t, IsJWT(session.AccessToken))
			assert.Equal(t, testCase.authCookies, session.AuthCookies)
		})
	}
}

func Test_Client_FetchConfig_second_fetch(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		beforeSecondFetch func(fake *fakePureVPN)
		counters          fakeCounters
	}{
		"access_token_reused": {
			counters: fakeCounters{passwordLogins: 1, tokens: 1},
		},
		"rejected_access_token_single_sign_on": {
			beforeSecondFetch: func(fake *fakePureVPN) {
				fake.rejectToken = fake.latestToken
			},
			counters: fakeCounters{passwordLogins: 1, tokens: 2},
		},
		"rejected_access_token_stale_cookie_ignored": {
			// The stale access token cookie must not be mistaken
			// for the result of the single sign-on login.
			beforeSecondFetch: func(fake *fakePureVPN) {
				fake.rejectToken = fake.latestToken
				fake.ssoDisabled = true
			},
			counters: fakeCounters{passwordLogins: 2, tokens: 2},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fake := newFakePureVPN(t)
			server := httptest.NewServer(fake)
			defer server.Close()

			credentials := Credentials{Username: testUsername, Password: testPassword}
			client := newTestClient(t, server.URL, credentials, Session{})
			_, err := client.FetchConfig(context.Background(), newTestRequest())
			require.NoError(t, err)
			firstToken := client.Session().AccessToken

			if testCase.beforeSecondFetch != nil {
				fake.mutex.Lock()
				testCase.beforeSecondFetch(fake)
				fake.mutex.Unlock()
			}

			config, err := client.FetchConfig(context.Background(), newTestRequest())
			require.NoError(t, err)
			assert.Equal(t, newExpectedConfig(), config)
			assert.Equal(t, testCase.counters, fake.getCounters())
			if testCase.counters.tokens > 1 {
				assert.NotEqual(t, firstToken, client.Session().AccessToken)
			}
		})
	}
}

type roundTripFunc func(request *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func Test_Client_FetchConfig_network_error(t *testing.T) {
	t.Parallel()

	errTest := errors.New("test network error")
	httpClient := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errTest
		}),
	}
	credentials := Credentials{Username: testUsername, Password: testPassword}
	client, err := New(httpClient, "", "", credentials, Session{})
	require.NoError(t, err)

	_, err = client.FetchConfig(context.Background(), newTestRequest())
	require.ErrorIs(t, err, errTest)
	assert.ErrorContains(t, err, "https://auth.purevpn.com/oauth2/authorize")
	assert.NotContains(t, err.Error(), "client_id")
	assert.False(t, IsAuthError(err))
}

func Test_Client_apiRequest(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		status     int
		headers    map[string]string
		body       string
		errWrapped error
		errMessage string
	}{
		"success": {
			status: http.StatusOK,
			body:   `{"status":true,"body":{"value":"x"}}`,
		},
		"unauthorized_status": {
			status:     http.StatusUnauthorized,
			errWrapped: errUnauthorized,
		},
		"forbidden_json": {
			status:     http.StatusForbidden,
			headers:    map[string]string{"Content-Type": "application/json"},
			body:       `{"status":false,"message":"Forbidden"}`,
			errWrapped: errUnauthorized,
		},
		"forbidden_empty": {
			status:     http.StatusForbidden,
			errWrapped: errUnauthorized,
		},
		"forbidden_html": {
			status:     http.StatusForbidden,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       "<html>Access denied</html>",
			errWrapped: errBlocked,
		},
		"forbidden_cloudflare": {
			status:     http.StatusForbidden,
			headers:    map[string]string{"Server": "cloudflare", "Content-Type": "text/html"},
			body:       "<html><title>Attention Required! | Cloudflare</title></html>",
			errWrapped: errBlocked,
			errMessage: "Cloudflare returned 403 Forbidden",
		},
		"cloudflare_challenge": {
			status:     http.StatusForbidden,
			headers:    map[string]string{"Cf-Mitigated": "challenge"},
			errWrapped: errBlocked,
		},
		"server_error": {
			status:     http.StatusInternalServerError,
			body:       "oops",
			errWrapped: errAPI,
			errMessage: "oops",
		},
		"html_instead_of_json": {
			status:     http.StatusOK,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       "<html>login</html>",
			errWrapped: errUnauthorized,
		},
		"invalid_json": {
			status:     http.StatusOK,
			body:       "not json",
			errWrapped: errUnexpectedResponse,
		},
		"token_expired_message": {
			status:     http.StatusOK,
			body:       `{"status":false,"message":"Token expired"}`,
			errWrapped: errUnauthorized,
		},
		"subscription_expired_message": {
			status:     http.StatusOK,
			body:       `{"status":false,"message":"Your subscription has expired"}`,
			errWrapped: errAPI,
			errMessage: "Your subscription has expired",
		},
		"invalid_body": {
			status:     http.StatusOK,
			body:       `{"status":true,"body":"text"}`,
			errWrapped: errUnexpectedResponse,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "Bearer token", r.Header.Get("Authorization"))
				for key, value := range testCase.headers {
					w.Header().Set(key, value)
				}
				w.WriteHeader(testCase.status)
				fmt.Fprint(w, testCase.body)
			}))
			defer server.Close()

			client := newTestClient(t, server.URL, Credentials{}, Session{})
			var body struct {
				Value string `json:"value"`
			}
			err := client.apiRequest(context.Background(), "token", "/v2/api/test", nil, &body)

			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			}
			if testCase.errWrapped == nil {
				assert.Equal(t, "x", body.Value)
			}
		})
	}
}

func Test_isAuthMessage(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		message string
		isAuth  bool
	}{
		"empty":                   {},
		"unauthorized":            {message: "Unauthorized", isAuth: true},
		"unauthorised":            {message: "Request unauthorised", isAuth: true}, //nolint:misspell
		"not_authenticated":       {message: "User is not authenticated", isAuth: true},
		"token_expired":           {message: "Token Expired", isAuth: true},
		"invalid_token":           {message: "Invalid token provided", isAuth: true},
		"token_is_invalid":        {message: "The token is invalid", isAuth: true},
		"subscription_expired":    {message: "Your subscription has expired"},
		"invalid_public_key":      {message: "Invalid public key token"},
		"session_limit":           {message: "Maximum session limit reached"},
		"login_country_not_found": {message: "Login server not found for country"},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, testCase.isAuth, isAuthMessage(testCase.message))
		})
	}
}

func Test_cookieJar(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		serverCookie *http.Cookie
		expected     map[string][]string
	}{
		"same_domain_and_path": {
			serverCookie: &http.Cookie{Name: "fusionauth.sso", Value: "new", Path: "/"},
			expected: map[string][]string{
				"fusionauth.sso":   {"new"},
				"fusionauth.trust": {"trusted"},
			},
		},
		"parent_domain": {
			serverCookie: &http.Cookie{Name: "fusionauth.sso", Value: "new", Domain: "example.com", Path: "/"},
			expected: map[string][]string{
				"fusionauth.sso":   {"new"},
				"fusionauth.trust": {"trusted"},
			},
		},
		"other_path": {
			serverCookie: &http.Cookie{Name: "fusionauth.sso", Value: "new", Path: "/oauth2"},
			expected: map[string][]string{
				"fusionauth.sso":   {"new"},
				"fusionauth.trust": {"trusted"},
			},
		},
		"other_cookie": {
			serverCookie: &http.Cookie{Name: "fusionauth.locale", Value: "en", Path: "/"},
			expected: map[string][]string{
				"fusionauth.sso":    {"old"},
				"fusionauth.trust":  {"trusted"},
				"fusionauth.locale": {"en"},
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			authURL, err := url.Parse("https://auth.example.com")
			require.NoError(t, err)
			authorizeURL := joinURL(authURL, "/oauth2/authorize")

			jar, err := newCookieJar(authURL)
			require.NoError(t, err)
			jar.restore(map[string]string{"fusionauth.sso": "old", "fusionauth.trust": "trusted"})
			jar.SetCookies(authorizeURL, []*http.Cookie{testCase.serverCookie})

			cookies := make(map[string][]string)
			for _, cookie := range jar.Cookies(authorizeURL) {
				cookies[cookie.Name] = append(cookies[cookie.Name], cookie.Value)
			}
			assert.Equal(t, testCase.expected, cookies)
		})
	}
}

func Test_redactURL(t *testing.T) {
	t.Parallel()

	fullURL, err := url.Parse("https://user:pass@my.purevpn.com/v2/api/fusionauth/login?code=secret&state=x#top")
	require.NoError(t, err)
	assert.Equal(t, "https://my.purevpn.com/v2/api/fusionauth/login", redactURL(fullURL))
}

func Test_accessTokenValid(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_000_000, 0)
	testCases := map[string]struct {
		token string
		valid bool
	}{
		"empty":           {},
		"opaque":          {token: "opaque-token", valid: true}, //nolint:gosec // test value
		"valid_jwt":       {token: makeJWT(now.Add(time.Hour), 0), valid: true},
		"expiring_jwt":    {token: makeJWT(now.Add(30*time.Second), 0)},
		"expired_jwt":     {token: makeJWT(now.Add(-time.Hour), 0)},
		"malformed_token": {token: "a.b.c", valid: true},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, testCase.valid, accessTokenValid(testCase.token, now))
		})
	}
}
