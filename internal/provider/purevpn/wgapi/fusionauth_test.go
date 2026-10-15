package wgapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseHTML(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		body          string
		forms         []*htmlForm
		errorMessages []string
	}{
		"inputs_nested_in_error_element": {
			body: `<form action="/oauth2/authorize">
<div class="form-row error">
<input name="loginId" type="text"><input name="password" type="password">
<span class="error">Invalid login credentials.</span>
</div></form>`,
			forms: []*htmlForm{{
				action: "/oauth2/authorize",
				inputs: []htmlInput{
					{name: "loginId", inputType: "text"},
					{name: "password", inputType: "password"},
				},
			}},
			errorMessages: []string{"Invalid login credentials."},
		},
		"hidden_errors_ignored": {
			body: `<template><div class="error">Captcha required</div></template>
<div class="error" hidden>Captcha hidden attribute</div>
<div role="alert" style="display: none">Captcha hidden style</div>
<p class="alert-error">Visible <script>var captcha = 1;</script>error</p>`,
			errorMessages: []string{"Visible error"},
		},
		"input_outside_form_and_alert": {
			body:          `<input name="ignored"><div role="alert">Alert <b>text</b></div>`,
			errorMessages: []string{"Alert text"},
		},
		"more_hidden_and_error_variants": {
			body: `<style>.error{}</style>
<noscript><div class="error">Enable JavaScript</div></noscript>
<div class="error" aria-hidden="true">Captcha aria hidden</div>
<div class="alert-danger" style="visibility: hidden">Captcha visibility hidden</div>
<div class="error"> </div>
<ul class="errors"><li>Errors list</li></ul>
<div class="alert alert-danger">Danger</div>
<form action="/f"><textarea name="comment"></textarea><select name="choice"></select></form>`,
			forms: []*htmlForm{{
				action: "/f",
				inputs: []htmlInput{{name: "comment"}, {name: "choice"}},
			}},
			errorMessages: []string{"Errors list", "Danger"},
		},
		"labels": {
			body: `<form action="/methods">
<label><input type="radio" name="methodId" value="m-email" checked> Email</label>
<input type="radio" id="auth" name="methodId" value="m-auth"><label for="auth">Authenticator app</label>
<button type="submit">Go</button>
</form>`,
			forms: []*htmlForm{{
				action: "/methods",
				inputs: []htmlInput{
					{name: "methodId", value: "m-email", inputType: "radio", checked: true, label: "Email"},
					{name: "methodId", value: "m-auth", id: "auth", inputType: "radio", label: "Authenticator app"},
					{inputType: "submit"},
				},
			}},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			forms, errorMessages := parseHTML([]byte(testCase.body))
			assert.Equal(t, testCase.forms, forms)
			assert.Equal(t, testCase.errorMessages, errorMessages)
		})
	}
}

func Test_loginPageError(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		errors     []string
		errWrapped error
		errMessage string
	}{
		"no_message": {
			errWrapped: errInvalidCredentials,
			errMessage: "login page shown again without error message",
		},
		"invalid_credentials": {
			errors:     []string{"Invalid login credentials."},
			errWrapped: errInvalidCredentials,
			errMessage: "Invalid login credentials.",
		},
		"captcha": {
			errors:     []string{"Please complete the CAPTCHA."},
			errWrapped: errCaptchaRequired,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := loginPageError(&htmlPage{errors: testCase.errors})
			assert.ErrorIs(t, err, testCase.errWrapped)
			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}

func Test_isTwoFactorMethodsForm(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		inputs  []htmlInput
		matches bool
	}{
		"no_input": {},
		"hidden_method": {
			inputs: []htmlInput{{name: "methodId", value: "m-email", inputType: "hidden"}},
		},
		"other_radio": {
			inputs: []htmlInput{{name: "choice", value: "m-email", inputType: "radio"}},
		},
		"radio_methods": {
			inputs: []htmlInput{
				{name: "twoFactorId", value: "tf-1", inputType: "hidden"},
				{name: "methodId", value: "m-auth", inputType: "radio"},
			},
			matches: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			form := &htmlForm{inputs: testCase.inputs}
			assert.Equal(t, testCase.matches, isTwoFactorMethodsForm(form))
		})
	}
}

func Test_htmlForm_values(t *testing.T) {
	t.Parallel()

	form := &htmlForm{inputs: []htmlInput{
		{name: "loginId", value: "user", inputType: "text"},
		{value: "no name", inputType: "text"},
		{name: "submit", value: "Login", inputType: "submit"},
		{name: "button", value: "Cancel", inputType: "button"},
		{name: "method", value: "m-email", inputType: "radio"},
		{name: "method", value: "m-auth", inputType: "radio", checked: true},
		{name: "remember", value: "true", inputType: "checkbox"},
		{name: "trust", value: "true", inputType: "checkbox", checked: true},
	}}

	assert.Equal(t, url.Values{
		"loginId": {"user"},
		"method":  {"m-auth"},
		"trust":   {"true"},
	}, form.values())
}

func Test_isLoginForm_isTwoFactorForm(t *testing.T) {
	t.Parallel()

	loginID := htmlInput{name: "loginId"}
	password := htmlInput{name: "password"}
	code := htmlInput{name: "code"}
	twoFactorID := htmlInput{name: "twoFactorId"}

	assert.True(t, isLoginForm(&htmlForm{inputs: []htmlInput{loginID, password}}))
	assert.False(t, isLoginForm(&htmlForm{inputs: []htmlInput{loginID}}))
	assert.False(t, isLoginForm(&htmlForm{inputs: []htmlInput{password}}))
	assert.True(t, isTwoFactorForm(&htmlForm{inputs: []htmlInput{code, twoFactorID}}))
	assert.False(t, isTwoFactorForm(&htmlForm{inputs: []htmlInput{code}}))
	assert.False(t, isTwoFactorForm(&htmlForm{inputs: []htmlInput{twoFactorID}}))
}

func Test_setDefault(t *testing.T) {
	t.Parallel()

	values := url.Values{"set": {"value"}, "empty": {""}}
	setDefault(values, "set", "default")
	setDefault(values, "empty", "default")
	setDefault(values, "missing", "default")

	assert.Equal(t, url.Values{
		"set":     {"value"},
		"empty":   {"default"},
		"missing": {"default"},
	}, values)
}

func Test_Client_submitForm_invalidAction(t *testing.T) {
	t.Parallel()

	client, err := New(&http.Client{}, "", "", Credentials{}, Session{})
	require.NoError(t, err)
	page := &htmlPage{url: client.authURL}

	_, err = client.submitForm(context.Background(), page, &htmlForm{action: "%zz"}, url.Values{})

	assert.EqualError(t, err, `parsing form action: parse "%zz": invalid URL escape "%zz"`)
}

func Test_Client_doAuthRequest(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		status     int
		rawURL     string
		errMessage string
	}{
		"invalid_url": {
			rawURL:     "://invalid",
			errMessage: `creating request: parse "://invalid": missing protocol scheme`,
		},
		"server_error": {
			status:     http.StatusInternalServerError,
			errMessage: "unexpected response from PureVPN: %s returned 500 Internal Server Error",
		},
		"client_error_page_parsed": {
			status: 499, // highest status code below the server errors
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(testCase.status)
				_, _ = w.Write([]byte(`<form action="/x"><input name="a"></form>`))
			}))
			t.Cleanup(server.Close)
			client := newTestClient(t, server.URL, Credentials{}, Session{})
			rawURL := testCase.rawURL
			if rawURL == "" {
				rawURL = server.URL + "/page?secret=1"
			}

			page, err := client.doAuthRequest(context.Background(), http.MethodGet, rawURL, nil)

			if testCase.errMessage != "" {
				errMessage := testCase.errMessage
				if testCase.rawURL == "" {
					errMessage = fmt.Sprintf(errMessage, server.URL+"/page")
				}
				assert.EqualError(t, err, errMessage)
				assert.Nil(t, page)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, []*htmlForm{{action: "/x", inputs: []htmlInput{{name: "a"}}}}, page.forms)
		})
	}
}

func Test_Client_loginWithCredentials_alreadyLoggedIn(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET /oauth2/authorize", r.Method+" "+r.URL.Path)
		// The browser session is still valid, so the auth server
		// redirects to the member area which sets the access token.
		http.SetCookie(w, &http.Cookie{Name: accessToken, Value: "token", Path: "/"})
		_, _ = w.Write([]byte("<html>dashboard</html>"))
	}))
	t.Cleanup(server.Close)
	credentials := Credentials{Username: testUsername, Password: testPassword}
	client := newTestClient(t, server.URL, credentials, Session{})

	token, err := client.loginWithCredentials(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "token", token)
}
