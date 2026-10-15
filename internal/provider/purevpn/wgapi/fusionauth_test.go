package wgapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
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

func Test_Client_submitForm(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		action     string
		errWrapped error
		errMessage string
	}{
		"invalid_action": {
			action:     "%zz",
			errMessage: `parsing form action: parse "%zz": invalid URL escape "%zz"`,
		},
		"other_host": {
			action:     "https://evil.example.com/oauth2/authorize",
			errWrapped: errHostNotAllowed,
			errMessage: "form action: host not allowed: evil.example.com",
		},
		"insecure_scheme": {
			action:     "http://auth.purevpn.com/oauth2/authorize",
			errWrapped: errHostNotAllowed,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			httpClient := &http.Client{
				Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					t.Error("unexpected request")
					return nil, errors.New("unexpected request")
				}),
			}
			client, err := New(httpClient, "", "", Credentials{}, Session{})
			require.NoError(t, err)
			page := &htmlPage{url: client.authURL}

			_, err = client.submitForm(t.Context(), page, &htmlForm{action: testCase.action},
				url.Values{"password": {"secret"}})

			if testCase.errWrapped != nil {
				assert.ErrorIs(t, err, testCase.errWrapped)
			}
			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}

func Test_Client_redirects(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		redirectTo    func(otherURL string) string
		checkRedirect func(request *http.Request, via []*http.Request) error
		errWrapped    error
		errMessage    string
		otherRequests uint
	}{
		"other_host": {
			redirectTo: func(otherURL string) string { return otherURL + "/steal" },
			errWrapped: errHostNotAllowed,
			errMessage: "redirect: host not allowed: ",
		},
		"redirect_loop": {
			redirectTo: func(string) string { return "/loop" },
			errWrapped: errUnexpectedResponse,
			errMessage: "stopped after 10 redirects",
		},
		"caller_check_redirect": {
			redirectTo: func(string) string { return "/loop" },
			checkRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			otherRequests := uint(0)
			var mutex sync.Mutex
			otherServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				mutex.Lock()
				otherRequests++
				mutex.Unlock()
			}))
			t.Cleanup(otherServer.Close)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				// 307 would replay the request body with the credentials.
				http.Redirect(writer, request, testCase.redirectTo(otherServer.URL), http.StatusTemporaryRedirect)
			}))
			t.Cleanup(server.Close)
			httpClient := &http.Client{Transport: &http.Transport{}, CheckRedirect: testCase.checkRedirect}
			client, err := New(httpClient, server.URL, server.URL, Credentials{}, Session{})
			require.NoError(t, err)

			_, err = client.doAuthRequest(t.Context(), http.MethodPost, server.URL+"/oauth2/authorize",
				url.Values{"password": {"secret"}})
			if testCase.errWrapped != nil {
				assert.ErrorIs(t, err, testCase.errWrapped)
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}

			err = client.apiRequest(t.Context(), "token", "/v2/api/subscription", nil, nil)
			if testCase.errWrapped != nil {
				assert.ErrorIs(t, err, testCase.errWrapped)
			}

			mutex.Lock()
			assert.Zero(t, otherRequests)
			mutex.Unlock()
		})
	}
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
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(testCase.status)
				_, _ = writer.Write([]byte(`<form action="/x"><input name="a"></form>`))
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
