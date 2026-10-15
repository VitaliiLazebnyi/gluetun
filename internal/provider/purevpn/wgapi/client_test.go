package wgapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
	twoFactor           bool
	twoFactorMethods    string // HTML radio inputs to show a method selection page
	twoFactorPageExtra  string // HTML added after the two-factor code form
	totpTime            time.Time
	rejectCodes         uint // number of valid two-factor codes to reject
	blockCodeSubmission uint // two-factor code submission number blocked by Cloudflare
	cloudflare          bool
	captcha             bool
	apiResponses        map[string]*fakeResponse // API response for a path
	subscriptions       []subscription
	noCityID            bool              // the city ID is not expected in the server request
	rejectToken         string            // API rejects this access token once
	ssoDisabled         bool              // ignore the single sign-on cookie
	pages               map[string]string // HTML page served for "METHOD /path"
	// State
	counters    fakeCounters
	latestToken string
	validTokens map[string]bool
}

type fakeCounters struct {
	authorizePages  uint
	passwordLogins  uint
	twoFactorLogins uint
	tokens          uint
}

type fakeResponse struct {
	status      int
	contentType string
	body        string
}

func (r *fakeResponse) write(writer http.ResponseWriter) {
	if r.contentType != "" {
		writer.Header().Set("Content-Type", r.contentType)
	}
	writer.WriteHeader(r.status)
	fmt.Fprint(writer, r.body)
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
</form>%s</body></html>`

// otherMethodForm is the form shown on the two-factor code page
// to send a code with another two-factor method.
const otherMethodForm = `<form action="/oauth2/two-factor-methods" method="post">
<input type="hidden" name="twoFactorId" value="tf-1">
<input type="hidden" name="methodId" value="m-email">
<button type="submit">Send a code by email instead</button>
</form>`

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

func (f *fakePureVPN) issueToken(writer http.ResponseWriter, request *http.Request) {
	f.counters.tokens++
	f.latestToken = makeJWT(time.Now().Add(time.Hour), f.counters.tokens)
	f.validTokens[f.latestToken] = true
	http.SetCookie(writer, &http.Cookie{Name: "fusionauth.sso", Value: testSSOCookie, Path: "/"})
	http.Redirect(writer, request, "/v2/api/fusionauth/login?code=abc", http.StatusFound)
}

func (f *fakePureVPN) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	if f.cloudflare {
		writeCloudflareBlock(writer)
		return
	}
	if request.Method+" "+request.URL.Path == "GET /oauth2/authorize" {
		f.counters.authorizePages++
	}
	page, ok := f.pages[request.Method+" "+request.URL.Path]
	if ok {
		fmt.Fprint(writer, page)
		return
	}

	baseURL := "http://" + request.Host
	switch request.Method + " " + request.URL.Path {
	case "GET /oauth2/authorize":
		f.serveAuthorizePage(writer, request, baseURL)
	case "POST /oauth2/authorize":
		if !f.parseForm(writer, request) {
			return
		}
		assert.Equal(f.t, clientID, request.PostForm.Get("client_id"))
		f.counters.passwordLogins++
		switch {
		case f.captcha:
			fmt.Fprintf(writer, loginPage, baseURL, " error", //nolint:gosec // test server
				`<span class="error">Please complete the captcha.</span>`)
		case request.PostForm.Get("loginId") != testUsername || request.PostForm.Get("password") != testPassword:
			fmt.Fprintf(writer, loginPage, baseURL, " error", //nolint:gosec // test server
				`<span class="error">Invalid login credentials.</span>`)
		case f.twoFactor && f.twoFactorMethods != "":
			fmt.Fprintf(writer, twoFactorMethodsPage, f.twoFactorMethods)
		case f.twoFactor:
			f.writeTwoFactorPage(writer, "")
		default:
			f.issueToken(writer, request)
		}
	case "POST /oauth2/two-factor-methods":
		if !f.parseForm(writer, request) {
			return
		}
		assert.Equal(f.t, "m-auth", request.PostForm.Get("methodId"))
		f.writeTwoFactorPage(writer, "")
	case "POST /oauth2/two-factor":
		f.serveTwoFactorCode(writer, request)
	case "GET /v2/api/fusionauth/login":
		http.SetCookie(writer, &http.Cookie{Name: accessToken, Value: f.latestToken, Path: "/"})
		http.Redirect(writer, request, "/v2/dashboard", http.StatusFound)
	case "GET /v2/dashboard":
		fmt.Fprint(writer, "<html>dashboard</html>")
	default:
		f.serveAPI(writer, request)
	}
}

func (f *fakePureVPN) serveAuthorizePage(writer http.ResponseWriter, request *http.Request, baseURL string) {
	cookie, err := request.Cookie("fusionauth.sso")
	switch {
	case err != nil, f.ssoDisabled:
	case cookie.Value == testSSOCookie:
		f.issueToken(writer, request)
		return
	case cookie.Value == "untrusted": // trusted device cookie expired
		f.writeTwoFactorPage(writer, "")
		return
	}
	fmt.Fprintf(writer, loginPage, baseURL, "", "") //nolint:gosec // test server
}

func writeCloudflareBlock(writer http.ResponseWriter) {
	writer.Header().Set("Server", "cloudflare")
	writer.WriteHeader(http.StatusForbidden)
	fmt.Fprint(writer, "<html><title>Just a moment...</title></html>")
}

func (f *fakePureVPN) writeTwoFactorPage(writer http.ResponseWriter, errorHTML string) {
	fmt.Fprintf(writer, twoFactorPage, errorHTML, f.twoFactorPageExtra)
}

func (f *fakePureVPN) serveTwoFactorCode(writer http.ResponseWriter, request *http.Request) {
	if !f.parseForm(writer, request) {
		return
	}
	f.counters.twoFactorLogins++
	if f.counters.twoFactorLogins == f.blockCodeSubmission {
		f.cloudflare = true
		writeCloudflareBlock(writer)
		return
	}
	assert.Equal(f.t, "tf-1", request.PostForm.Get("twoFactorId"))
	assert.Equal(f.t, "true", request.PostForm.Get("trustComputer"))
	valid, err := totp.ValidateCustom(request.PostForm.Get("code"), testTOTPSecret, f.totpTime, totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	assert.NoError(f.t, err)
	if !valid || f.rejectCodes > 0 {
		if valid {
			f.rejectCodes--
		}
		f.writeTwoFactorPage(writer, `<div class="error">Invalid code</div>`)
		return
	}
	http.SetCookie(writer, &http.Cookie{Name: "fusionauth.trust", Value: "trusted", Path: "/"})
	f.issueToken(writer, request)
}

func (f *fakePureVPN) serveAPI(writer http.ResponseWriter, request *http.Request) {
	token := strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")
	if token == f.rejectToken || !f.validTokens[token] {
		f.rejectToken = ""
		delete(f.validTokens, token)
		// The real API answers like this for any token it does not accept.
		fmt.Fprint(writer, `{"status":false,"message":"Token is expired","error_code":"token_expired","errors":[]}`)
		return
	}
	if !f.parseForm(writer, request) {
		return
	}

	subscriptions := f.subscriptions
	if subscriptions == nil {
		subscriptions = []subscription{
			{ID: "expired", State: "expired", VPNUsernames: []string{"purevpn0sexpired"}},
			{ID: testSubsID, State: "active", VPNUsernames: []string{testVPNUsername}},
		}
	}

	response, ok := f.apiResponses[request.URL.Path]
	if ok {
		response.write(writer)
		return
	}

	var body any
	switch request.URL.Path {
	case "/v2/api/subscription":
		body = subscriptions
	case "/v2/api/wireguard/get-encrypt-password":
		assert.Equal(f.t, testVPNUsername, request.PostForm.Get("username"))
		body = map[string]string{"encrypPass": "encrypted"}
	case "/v2/api/wireguard/get-wg-server":
		assert.Equal(f.t, testVPNUsername, request.PostForm.Get("sUsername"))
		assert.Equal(f.t, "encrypted", request.PostForm.Get("sPassword"))
		assert.Equal(f.t, "US", request.PostForm.Get("sCountrySlug"))
		if f.noCityID {
			assert.False(f.t, request.PostForm.Has("iCityId"))
		} else {
			assert.Equal(f.t, "8778", request.PostForm.Get("iCityId"))
		}
		assert.Equal(f.t, testSubsID, request.PostForm.Get("sSubsId"))
		assert.Equal(f.t, testClientKey, request.PostForm.Get("sClientPublicKey"))
		server := map[string]string{
			"protocol_ip": "203.0.113.7",
			"wireguard_configuration": "[Interface]\nPrivateKey={clientPrivateKey}\n" +
				"Address=172.21.7.9\nDNS=103.109.1.1,103.109.1.2\n[Peer]\n" +
				"PublicKey=" + testServerKey + "\nAllowedIPs=0.0.0.0/0\n" +
				"Endpoint=us-ny.purevpn.net:51820\nPersistentKeepalive=21\n",
		}
		body = []map[string]string{server}
	default:
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	bodyJSON, err := json.Marshal(body)
	if !assert.NoError(f.t, err) {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	err = json.NewEncoder(writer).Encode(apiResponse{Status: true, Body: bodyJSON})
	assert.NoError(f.t, err)
}

func (f *fakePureVPN) parseForm(writer http.ResponseWriter, request *http.Request) (ok bool) {
	const maxBodySize = 1 << 20
	request.Body = http.MaxBytesReader(writer, request.Body, maxBodySize)
	err := request.ParseForm()
	if !assert.NoError(f.t, err) {
		http.Error(writer, err.Error(), http.StatusBadRequest)
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
	// A dedicated transport is used since closing a test server closes
	// the idle connections of the default transport, used by other tests.
	httpClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{}}
	client, err := New(httpClient, serverURL, serverURL, credentials, session)
	require.NoError(t, err)
	return client
}

func newExpectedConfig(t *testing.T) Config {
	t.Helper()
	serverKey, err := wgtypes.ParseKey(testServerKey)
	require.NoError(t, err)
	return Config{
		Addresses:           []netip.Prefix{netip.MustParsePrefix("172.21.7.9/32")},
		ServerPublicKey:     serverKey,
		EndpointHost:        "us-ny.purevpn.net",
		EndpointPort:        51820,
		PersistentKeepalive: 21 * time.Second,
		ProtocolIP:          netip.MustParseAddr("203.0.113.7"),
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
	loginPageAgain := fmt.Sprintf(loginPage, "http://127.0.0.1", " error",
		`<span class="error">Invalid login credentials.</span>`)

	testCases := map[string]struct {
		setup        func(fake *fakePureVPN)
		credentials  Credentials
		session      Session
		request      func(request *ServerRequest)
		ctxTimeout   time.Duration
		errWrapped   error
		errMessage   string
		authError    bool
		captchaError bool
		authCookies  map[string]string
		counters     fakeCounters
	}{
		"password_login": {
			credentials: credentials,
			authCookies: ssoCookies,
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1, tokens: 1},
		},
		"invalid_credentials": {
			credentials: Credentials{Username: testUsername, Password: "wrong"},
			errWrapped:  errInvalidCredentials,
			errMessage:  "Invalid login credentials.",
			authError:   true,
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1},
		},
		"captcha_required": {
			setup:        func(fake *fakePureVPN) { fake.captcha = true },
			credentials:  credentials,
			errWrapped:   errCaptchaRequired,
			errMessage:   "Please complete the captcha.",
			captchaError: true,
			counters:     fakeCounters{authorizePages: 1, passwordLogins: 1},
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
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1},
		},
		"two_factor_with_valid_secret": {
			setup:       func(fake *fakePureVPN) { fake.twoFactor = true },
			credentials: credentialsWithTOTP,
			authCookies: trustedCookies,
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1, twoFactorLogins: 1, tokens: 1},
		},
		"two_factor_with_wrong_secret": {
			setup: func(fake *fakePureVPN) { fake.twoFactor = true },
			credentials: Credentials{ //nolint:gosec // test value
				Username: testUsername, Password: testPassword, TOTPSecret: "GEZDGNBVGY3TQOJQ",
			},
			errWrapped: errTwoFactorCodeInvalid,
			errMessage: "Invalid code",
			authError:  true,
			counters:   fakeCounters{authorizePages: 1, passwordLogins: 1, twoFactorLogins: 2},
		},
		"two_factor_code_rejected_once": {
			setup: func(fake *fakePureVPN) {
				fake.twoFactor = true
				fake.rejectCodes = 1
			},
			credentials: credentialsWithTOTP,
			authCookies: trustedCookies,
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1, twoFactorLogins: 2, tokens: 1},
		},
		"two_factor_code_retry_blocked": {
			setup: func(fake *fakePureVPN) {
				fake.twoFactor = true
				fake.rejectCodes = 1
				fake.blockCodeSubmission = 2
			},
			credentials: credentialsWithTOTP,
			errWrapped:  errBlocked,
			errMessage:  "submitting two-factor code",
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1, twoFactorLogins: 2},
		},
		"two_factor_wait_canceled": {
			setup: func(fake *fakePureVPN) {
				fake.twoFactor = true
				fake.rejectCodes = 1
			},
			credentials: credentialsWithTOTP,
			ctxTimeout:  2 * time.Second,
			errWrapped:  context.DeadlineExceeded,
			errMessage:  "waiting for the next two-factor code",
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1, twoFactorLogins: 1},
		},
		"two_factor_invalid_secret": {
			setup: func(fake *fakePureVPN) { fake.twoFactor = true },
			credentials: Credentials{
				Username: testUsername, Password: testPassword, TOTPSecret: "INVALID1",
			},
			errMessage: "generating two-factor code from TOTP secret",
			counters:   fakeCounters{authorizePages: 1, passwordLogins: 1},
		},
		"two_factor_code_page_with_other_method_form": {
			setup: func(fake *fakePureVPN) {
				fake.twoFactor = true
				fake.twoFactorPageExtra = otherMethodForm
			},
			credentials: credentialsWithTOTP,
			authCookies: trustedCookies,
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1, twoFactorLogins: 1, tokens: 1},
		},
		"login_page_after_two_factor_code": {
			setup: func(fake *fakePureVPN) {
				fake.twoFactor = true
				fake.pages = map[string]string{"POST /oauth2/two-factor": loginPageAgain}
			},
			credentials: credentialsWithTOTP,
			errWrapped:  errUnexpectedResponse,
			errMessage:  "no access token after logging in, landed on",
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1},
		},
		"unknown_page_after_password": {
			setup: func(fake *fakePureVPN) {
				fake.pages = map[string]string{"POST /oauth2/authorize": "<html>maintenance</html>"}
			},
			credentials: credentials,
			errWrapped:  errUnexpectedResponse,
			errMessage:  "no access token after logging in, landed on",
			counters:    fakeCounters{authorizePages: 1},
		},
		"two_factor_method_selection": {
			setup: func(fake *fakePureVPN) {
				fake.twoFactor = true
				fake.twoFactorMethods = emailMethod + authenticatorMethod
			},
			credentials: credentialsWithTOTP,
			authCookies: trustedCookies,
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1, twoFactorLogins: 1, tokens: 1},
		},
		"two_factor_method_unsupported": {
			setup: func(fake *fakePureVPN) {
				fake.twoFactor = true
				fake.twoFactorMethods = emailMethod + smsMethod
			},
			credentials: credentialsWithTOTP,
			errWrapped:  errTwoFactorMethodUnsupported,
			authError:   true,
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1},
		},
		"two_factor_methods_page_on_authorize": {
			// The single sign-on session is valid but the trusted device
			// cookie expired, and the authorize page asks for a method.
			setup: func(fake *fakePureVPN) {
				fake.twoFactor = true
				fake.pages = map[string]string{
					"GET /oauth2/authorize": fmt.Sprintf(twoFactorMethodsPage, emailMethod+authenticatorMethod),
				}
			},
			credentials: credentialsWithTOTP,
			authCookies: trustedCookies,
			counters:    fakeCounters{authorizePages: 1, twoFactorLogins: 1, tokens: 1},
		},
		"stored_session_without_credentials": {
			setup:       func(fake *fakePureVPN) { fake.twoFactor = true }, // must not matter
			session:     Session{AuthCookies: ssoCookies},
			authCookies: ssoCookies,
			counters:    fakeCounters{authorizePages: 1, tokens: 1},
		},
		"expired_stored_session_falls_back_on_credentials": {
			credentials: credentials,
			session: Session{
				AccessToken: makeJWT(time.Now().Add(-time.Hour), 0),
				AuthCookies: map[string]string{"fusionauth.sso": "expired"},
			},
			authCookies: ssoCookies,
			// The login page is only loaded once.
			counters: fakeCounters{authorizePages: 1, passwordLogins: 1, tokens: 1},
		},
		"expired_stored_session_without_credentials": {
			session:    Session{AuthCookies: map[string]string{"fusionauth.sso": "expired"}},
			errWrapped: errSessionExpired,
			errMessage: "PureVPN account username and password are not set",
			authError:  true,
			counters:   fakeCounters{authorizePages: 1},
		},
		"stored_session_with_expired_trusted_device": {
			setup:       func(fake *fakePureVPN) { fake.twoFactor = true },
			credentials: credentialsWithTOTP,
			session:     Session{AuthCookies: map[string]string{"fusionauth.sso": "untrusted"}},
			authCookies: trustedCookies,
			counters:    fakeCounters{authorizePages: 1, twoFactorLogins: 1, tokens: 1},
		},
		"login_form_not_found": {
			setup: func(fake *fakePureVPN) {
				fake.pages = map[string]string{"GET /oauth2/authorize": "<html>no form</html>"}
			},
			credentials: credentials,
			session:     Session{AuthCookies: map[string]string{"fusionauth.sso": "stale"}},
			errWrapped:  errUnexpectedResponse,
			errMessage:  "login form not found",
			counters:    fakeCounters{authorizePages: 1},
		},
		"rejected_access_token_triggers_login": {
			credentials: credentials,
			// The token looks valid locally but the API rejects it.
			session:     Session{AccessToken: makeJWT(time.Now().Add(time.Hour), 0)},
			authCookies: ssoCookies,
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1, tokens: 1},
		},
		"rejected_access_token_without_credentials": {
			session:    Session{AccessToken: makeJWT(time.Now().Add(time.Hour), 0)},
			errWrapped: errCredentialsNotSet,
			errMessage: "logging in again after access token was rejected",
			authError:  true,
		},
		"cloudflare_block": {
			setup:       func(fake *fakePureVPN) { fake.cloudflare = true },
			credentials: credentials,
			errWrapped:  errBlocked,
			errMessage:  "loading login page",
		},
		"no_active_subscription": {
			setup: func(fake *fakePureVPN) {
				fake.subscriptions = []subscription{{ID: "old", State: "expired", VPNUsernames: []string{"x"}}}
			},
			credentials: credentials,
			errWrapped:  errNoActiveSubscription,
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1, tokens: 1},
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
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1, tokens: 1},
		},
		"subscription_selected_by_vpn_username": {
			setup: func(fake *fakePureVPN) {
				fake.subscriptions = []subscription{
					{ID: "no-username", State: "active"},
					{ID: "other", State: "Active", VPNUsernames: []string{"purevpn0sother"}},
					{ID: testSubsID, State: "active", VPNUsernames: []string{"purevpn0sother2", testVPNUsername}},
				}
			},
			credentials: credentials,
			request:     func(request *ServerRequest) { request.VPNUsername = testVPNUsername },
			authCookies: ssoCookies,
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1, tokens: 1},
		},
		"subscription_not_found_without_subscriptions": {
			setup:       func(fake *fakePureVPN) { fake.subscriptions = []subscription{} },
			credentials: credentials,
			request:     func(request *ServerRequest) { request.SubscriptionID = testSubsID },
			errWrapped:  errSubscriptionNotFound,
			errMessage:  "available subscriptions are none",
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1, tokens: 1},
		},
		"subscription_not_found": {
			credentials: credentials,
			request:     func(request *ServerRequest) { request.VPNUsername = "purevpn0sother" },
			errWrapped:  errSubscriptionNotFound,
			errMessage: "available subscriptions are expired (expired) with 1 VPN username(s); " +
				testSubsID + " (active) with 1 VPN username(s)",
			counters: fakeCounters{authorizePages: 1, passwordLogins: 1, tokens: 1},
		},
		"encrypted_password_empty": {
			setup: func(fake *fakePureVPN) {
				fake.apiResponses = map[string]*fakeResponse{"/v2/api/wireguard/get-encrypt-password": {
					status: http.StatusOK, body: `{"status":true,"body":{"encrypPass":""}}`,
				}}
			},
			credentials: credentials,
			errWrapped:  errUnexpectedResponse,
			errMessage:  "getting VPN password: unexpected response from PureVPN: encrypted password is empty",
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1, tokens: 1},
		},
		"wireguard_server_list_empty": {
			setup: func(fake *fakePureVPN) {
				fake.apiResponses = map[string]*fakeResponse{"/v2/api/wireguard/get-wg-server": {
					status: http.StatusOK, body: `{"status":true,"body":[]}`,
				}}
			},
			credentials: credentials,
			errWrapped:  errUnexpectedResponse,
			errMessage:  "getting WireGuard server: unexpected response from PureVPN: no WireGuard configuration",
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1, tokens: 1},
		},
		"wireguard_server_invalid_protocol_ip": {
			setup: func(fake *fakePureVPN) {
				fake.apiResponses = map[string]*fakeResponse{"/v2/api/wireguard/get-wg-server": {
					status: http.StatusOK,
					body: `{"status":true,"body":[{"protocol_ip":"not-an-ip","wireguard_configuration":` +
						`"[Interface]\nAddress=172.21.7.9\n[Peer]\nPublicKey=` + testServerKey +
						`\nEndpoint=us-ny.purevpn.net:51820\n"}]}`,
				}}
			},
			credentials: credentials,
			errWrapped:  errUnexpectedResponse,
			errMessage:  "parsing protocol IP",
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1, tokens: 1},
		},
		"no_city_id": {
			setup:       func(fake *fakePureVPN) { fake.noCityID = true },
			credentials: credentials,
			request:     func(request *ServerRequest) { request.CityID = 0 },
			authCookies: ssoCookies,
			counters:    fakeCounters{authorizePages: 1, passwordLogins: 1, tokens: 1},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// The client clock is set 1ms before the next TOTP time
			// step, so retrying a rejected code only waits 1ms.
			const timeStepSeconds = 30
			now := time.Unix((time.Now().Unix()/timeStepSeconds+1)*timeStepSeconds, 0).Add(-time.Millisecond)
			fake := newFakePureVPN(t)
			fake.totpTime = now
			if testCase.setup != nil {
				testCase.setup(fake)
			}
			server := httptest.NewServer(fake)
			defer server.Close()

			client := newTestClient(t, server.URL, testCase.credentials, testCase.session)
			client.timeNow = func() time.Time { return now }
			ctx := context.Background()
			if testCase.ctxTimeout > 0 {
				// Set the clock at the start of a time step, so retrying
				// a rejected code waits for about 30 seconds.
				client.timeNow = func() time.Time { return now.Add(time.Millisecond) }
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, testCase.ctxTimeout)
				defer cancel()
			}
			request := newTestRequest()
			if testCase.request != nil {
				testCase.request(&request)
			}
			config, err := client.FetchConfig(ctx, request)

			if testCase.errWrapped != nil || testCase.errMessage == "" {
				assert.ErrorIs(t, err, testCase.errWrapped)
			}
			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			}
			assert.Equal(t, testCase.authError, IsAuthError(err))
			assert.Equal(t, testCase.captchaError, IsCaptchaError(err))
			assert.Equal(t, testCase.counters, fake.getCounters())
			if err != nil {
				return
			}
			assert.Equal(t, newExpectedConfig(t), config)
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
			counters: fakeCounters{authorizePages: 1, passwordLogins: 1, tokens: 1},
		},
		"rejected_access_token_single_sign_on": {
			beforeSecondFetch: func(fake *fakePureVPN) {
				fake.rejectToken = fake.latestToken
			},
			counters: fakeCounters{authorizePages: 2, passwordLogins: 1, tokens: 2},
		},
		"rejected_access_token_stale_cookie_ignored": {
			// The stale access token cookie must not be mistaken
			// for the result of the single sign-on login.
			beforeSecondFetch: func(fake *fakePureVPN) {
				fake.rejectToken = fake.latestToken
				fake.ssoDisabled = true
			},
			counters: fakeCounters{authorizePages: 2, passwordLogins: 2, tokens: 2},
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
			assert.Equal(t, newExpectedConfig(t), config)
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

func Test_New(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		authURL    string
		appURL     string
		errMessage string
	}{
		"defaults": {},
		"invalid_auth_url": {
			authURL:    "://auth",
			errMessage: "parsing auth URL",
		},
		"invalid_app_url": {
			appURL:     "://app",
			errMessage: "parsing app URL",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client, err := New(&http.Client{}, testCase.authURL, testCase.appURL, Credentials{}, Session{})
			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
				assert.Nil(t, client)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, DefaultAuthURL, client.authURL.String())
			assert.Equal(t, DefaultAppURL, client.appURL.String())
		})
	}
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
		nilBody    bool
		errWrapped error
		errMessage string
	}{
		"success": {
			status: http.StatusOK,
			body:   `{"status":true,"body":{"value":"x"}}`,
		},
		"token_expired": {
			status:     http.StatusOK,
			body:       `{"status":false,"message":"Token is expired","error_code":"token_expired","errors":[]}`,
			errWrapped: errUnauthorized,
			errMessage: "Token is expired",
		},
		"api_error": {
			status:     http.StatusOK,
			body:       `{"status":false,"message":"Your subscription has expired","error_code":"other"}`,
			errWrapped: errAPI,
			errMessage: "Your subscription has expired",
		},
		"unauthorized_status": {
			status:     http.StatusUnauthorized,
			errWrapped: errUnauthorized,
		},
		"forbidden_json": {
			status:     http.StatusForbidden,
			headers:    map[string]string{"Content-Type": "application/json"},
			body:       `{"status":false,"message":"Forbidden"}`,
			errWrapped: errAPI,
			errMessage: "API returned 403 Forbidden: {",
		},
		"forbidden_html": {
			status:     http.StatusForbidden,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       "<html>Access denied</html>",
			errWrapped: errBlocked,
			errMessage: "API returned 403 Forbidden with an HTML page",
		},
		"cloudflare_challenge": {
			status:     http.StatusForbidden,
			headers:    map[string]string{"Cf-Mitigated": "challenge"},
			errWrapped: errBlocked,
			errMessage: "Cloudflare challenge",
		},
		"cloudflare_error_page": {
			status:     http.StatusServiceUnavailable,
			headers:    map[string]string{"Server": "cloudflare", "Content-Type": "text/html"},
			body:       `<html><div id="cf-error-details">Error</div></html>`,
			errWrapped: errBlocked,
			errMessage: "Cloudflare returned 503 Service Unavailable",
		},
		"server_error": {
			status:     http.StatusInternalServerError,
			body:       "oops",
			errWrapped: errAPI,
			errMessage: "oops",
		},
		"html_body_with_json_content_type": {
			status:     http.StatusOK,
			headers:    map[string]string{"Content-Type": "application/json"},
			body:       "  <html>login</html>",
			errWrapped: errUnauthorized,
			errMessage: "API returned an HTML page",
		},
		"invalid_json": {
			status:     http.StatusOK,
			body:       "not json",
			errWrapped: errUnexpectedResponse,
		},
		"invalid_body": {
			status:     http.StatusOK,
			body:       `{"status":true,"body":"text"}`,
			errWrapped: errUnexpectedResponse,
		},
		"body_ignored": {
			status:  http.StatusOK,
			body:    `{"status":true,"body":"text"}`,
			nilBody: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				assert.Equal(t, "Bearer token", request.Header.Get("Authorization"))
				assert.Equal(t, "application/json", request.Header.Get("Accept"))
				for key, value := range testCase.headers {
					writer.Header().Set(key, value)
				}
				writer.WriteHeader(testCase.status)
				fmt.Fprint(writer, testCase.body)
			}))
			defer server.Close()

			client := newTestClient(t, server.URL, Credentials{}, Session{})
			var body struct {
				Value string `json:"value"`
			}
			var bodyTarget any = &body
			if testCase.nilBody {
				bodyTarget = nil
			}
			err := client.apiRequest(context.Background(), "token", "/v2/api/test", nil, bodyTarget)

			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			}
			if testCase.errWrapped == nil && !testCase.nilBody {
				assert.Equal(t, "x", body.Value)
			}
		})
	}
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
		"not_json":        {token: "a.bm90LWpzb24.c", valid: true}, //nolint:gosec // test value
		// eyJqdGkiOjF9 is {"jti":1}, a JWT payload without expiry.
		"jwt_without_expiry": {token: "a.eyJqdGkiOjF9.c", valid: true}, //nolint:gosec // test value
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, testCase.valid, accessTokenValid(testCase.token, now))
		})
	}
}

func Test_truncate(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "text", truncate("  text \n"))
	maxLengthText := strings.Repeat("é", 200)
	assert.Equal(t, maxLengthText, truncate(maxLengthText))
	assert.Equal(t, maxLengthText+"...", truncate(maxLengthText+"y"))
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("test read error") }

func Test_Client_readBodyError(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(errorReader{}),
				Request:    request,
			}, nil
		}),
	}
	client, err := New(httpClient, "", "", Credentials{}, Session{})
	require.NoError(t, err)

	err = client.apiRequest(context.Background(), "token", "/v2/api/test", nil, nil)
	assert.EqualError(t, err, "reading response body: test read error")

	page, err := client.doAuthRequest(context.Background(), http.MethodGet, DefaultAuthURL, nil)
	assert.EqualError(t, err, "reading response body: test read error")
	assert.Nil(t, page)
}

type timeoutError struct{}

func (timeoutError) Error() string { return "test timeout" }
func (timeoutError) Timeout() bool { return true }

func Test_wrapRequestError(t *testing.T) {
	t.Parallel()

	errTest := errors.New("test error")
	testCases := map[string]struct {
		err        error
		errMessage string
	}{
		"not_url_error": {
			err:        errTest,
			errMessage: "test error",
		},
		"url_redacted": {
			err:        &url.Error{Op: "Get", URL: "https://auth.example.com/path?code=secret", Err: errTest},
			errMessage: `Get "https://auth.example.com/path": test error`,
		},
		"unparsable_url": {
			err:        &url.Error{Op: "Get", URL: "https://auth.example.com/%zz?code=secret", Err: errTest},
			errMessage: `Get "<redacted>": test error`,
		},
		"timeout": {
			err: &url.Error{Op: "Get", URL: "https://auth.example.com/path?code=secret", Err: timeoutError{}},
			errMessage: `timed out reaching PureVPN: Get "https://auth.example.com/path": ` +
				"test timeout",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := wrapRequestError(testCase.err)
			assert.EqualError(t, err, testCase.errMessage)
			assert.ErrorIs(t, err, testCase.err)
		})
	}
}

func Test_Client_saveSession(t *testing.T) {
	t.Parallel()

	client, err := New(&http.Client{}, "https://auth.example.com", "https://app.example.com",
		Credentials{}, Session{})
	require.NoError(t, err)
	client.httpClient.Jar.SetCookies(client.authURL, []*http.Cookie{
		{Name: "fusionauth.sso", Value: "general", Path: "/"},
		{Name: "fusionauth.sso", Value: "specific", Path: "/oauth2"},
		{Name: "fusionauth.trust", Value: "trusted", Path: "/"},
		{Name: "other", Value: "x", Path: "/"},
	})

	client.saveSession("token")

	assert.Equal(t, Session{
		AccessToken: "token",
		AuthCookies: map[string]string{"fusionauth.sso": "specific", "fusionauth.trust": "trusted"},
	}, client.Session())
}

func Test_Client_login_credentialsNotSet(t *testing.T) {
	t.Parallel()

	testCases := map[string]Credentials{
		"nothing_set":      {},
		"password_not_set": {Username: testUsername},
		"username_not_set": {Password: testPassword},
	}

	for name, credentials := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			httpClient := &http.Client{
				Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					t.Error("unexpected request")
					return nil, errors.New("unexpected request")
				}),
			}
			client, err := New(httpClient, "", "", credentials, Session{})
			require.NoError(t, err)

			token, err := client.login(context.Background())

			assert.Empty(t, token)
			assert.EqualError(t, err, errCredentialsNotSet.Error())
		})
	}
}

func Test_joinURL(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		base     string
		path     string
		expected string
	}{
		"empty_base_path": {base: "https://example.com", path: "/v2/api", expected: "https://example.com/v2/api"},
		"base_path": {
			base: "https://example.com/base", path: "/v2/api", expected: "https://example.com/base/v2/api",
		},
		"base_path_trailing": {base: "https://example.com/base/", path: "v2", expected: "https://example.com/base/v2"},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			base, err := url.Parse(testCase.base)
			require.NoError(t, err)
			assert.Equal(t, testCase.expected, joinURL(base, testCase.path).String())
		})
	}
}

func Test_Session_WithSessionToken(t *testing.T) {
	t.Parallel()

	jwt := makeJWT(time.Unix(1_000_000, 0), 0)
	testCases := map[string]struct {
		session  Session
		token    string
		expected Session
	}{
		"jwt_on_empty_session": {
			token:    jwt,
			expected: Session{AccessToken: jwt},
		},
		"jwt_keeps_cookies": {
			session:  Session{AccessToken: "old", AuthCookies: map[string]string{"fusionauth.trust": "trusted"}},
			token:    jwt,
			expected: Session{AccessToken: jwt, AuthCookies: map[string]string{"fusionauth.trust": "trusted"}},
		},
		"sso_cookie_on_empty_session": {
			token:    "sso",
			expected: Session{AuthCookies: map[string]string{"fusionauth.sso": "sso"}},
		},
		"sso_cookie_clears_access_token": {
			session: Session{AccessToken: "old", AuthCookies: map[string]string{
				"fusionauth.sso": "old", "fusionauth.trust": "trusted",
			}},
			token: "sso",
			expected: Session{AuthCookies: map[string]string{
				"fusionauth.sso": "sso", "fusionauth.trust": "trusted",
			}},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			originalCookies := maps.Clone(testCase.session.AuthCookies)
			updated := testCase.session.WithSessionToken(testCase.token)
			assert.Equal(t, testCase.expected, updated)
			assert.Equal(t, originalCookies, testCase.session.AuthCookies, "session given must not be modified")
		})
	}
}
