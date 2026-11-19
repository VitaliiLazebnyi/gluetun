package wgapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
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
		"inputs_after_form_end": {
			body: `<form action="/first"><input name="a" value="1"><button name="go" value="x">Go</button></form>
<input name="after_first" value="2">
<form action="/second"><input name="b" value="3"></form>
<input name="after_second" value="4">`,
			forms: []*htmlForm{
				{
					action: "/first",
					inputs: []htmlInput{
						{name: "a", value: "1"},
						{name: "go", value: "x", inputType: "submit"},
					},
				},
				{
					action: "/second",
					inputs: []htmlInput{{name: "b", value: "3"}},
				},
			},
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
<div class="alert alert-danger">Danger</div>`,
			errorMessages: []string{"Errors list", "Danger"},
		},
		"two_factor_form": {
			body: `<form action="/oauth2/two-factor">
<input type="hidden" name="twoFactorId" value="tf-1"><input type="hidden" name="methodId" value="m-auth">
<label for="code">Code</label><input id="code" name="code" type="text">
<label><input type="checkbox" name="trustComputer" value="true"> Trust this computer</label>
<button type="submit">Verify</button>
</form>`,
			forms: []*htmlForm{{
				action: "/oauth2/two-factor",
				inputs: []htmlInput{
					{name: "twoFactorId", value: "tf-1", inputType: "hidden"},
					{name: "methodId", value: "m-auth", inputType: "hidden"},
					{name: "code", inputType: "text"},
					{name: "trustComputer", value: "true", inputType: "checkbox"},
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

func Test_totpCode(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_000_000, 0)
	testCases := map[string]struct {
		secret         string
		expectedSecret string
		errMessage     string
	}{
		"unpadded": {
			secret:         testTOTPSecret,
			expectedSecret: testTOTPSecret,
		},
		"lowercase_with_spaces": { //nolint:gosec // test value
			secret:         "jbsw y3dp ehpk 3pxp",
			expectedSecret: testTOTPSecret,
		},
		"extra_padding": {
			secret:         testTOTPSecret + "====",
			expectedSecret: testTOTPSecret,
		},
		"padded": { //nolint:gosec // test value
			secret:         "JBSWY3DPEE======",
			expectedSecret: "JBSWY3DPEE",
		},
		"invalid_secret": {
			secret:     "INVALID1",
			errMessage: "generating two-factor code from TOTP secret: Decoding of secret as base32 failed.",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			code, err := totpCode(testCase.secret, now)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
				assert.Empty(t, code)
				return
			}
			require.NoError(t, err)
			expectedCode, err := totp.GenerateCode(testCase.expectedSecret, now)
			require.NoError(t, err)
			assert.Equal(t, expectedCode, code)
		})
	}
}

func Test_loginPageError(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		errors     []string
		errMessage string
	}{
		"no_message": {
			errMessage: "PureVPN rejected the account username or password: login page shown again without error message",
		},
		"invalid_credentials": {
			errors:     []string{"Invalid login credentials."},
			errMessage: "PureVPN rejected the account username or password: Invalid login credentials.",
		},
		"captcha": {
			errors:     []string{"Please complete the CAPTCHA."},
			errMessage: "PureVPN requires a captcha to log in, log in once from a browser or set a session token",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := loginPageError(&htmlPage{errors: testCase.errors})
			assert.ErrorContains(t, err, testCase.errMessage)
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
		{name: "remember", value: "true", inputType: "checkbox"},
		{name: "trust", value: "true", inputType: "checkbox", checked: true},
	}}

	assert.Equal(t, url.Values{
		"loginId": {"user"},
		"trust":   {"true"},
	}, form.values())

	// The button without type is a submit button, and the input
	// after the form end is not part of the form.
	forms, _ := parseHTML([]byte(`<form><input name="loginId" value="user">` +
		`<button name="action" value="cancel">Cancel</button></form><input name="other" value="x">`))
	require.Len(t, forms, 1)
	assert.Equal(t, url.Values{"loginId": {"user"}}, forms[0].values())
}

func Test_Client_submitForm(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		action     string
		errMessage string
	}{
		"invalid_action": {
			action:     "%zz",
			errMessage: `parsing form action: parse "%zz": invalid URL escape "%zz"`,
		},
		"other_host": {
			action:     "https://evil.example.com/oauth2/authorize",
			errMessage: "form action: host not allowed: evil.example.com",
		},
		"insecure_scheme": {
			action:     "http://auth.purevpn.com/oauth2/authorize",
			errMessage: "host not allowed",
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

			assert.ErrorContains(t, err, testCase.errMessage)
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

			page, err := client.doAuthRequest(t.Context(), http.MethodGet, rawURL, nil)

			if testCase.errMessage != "" {
				errMessage := testCase.errMessage
				if testCase.rawURL == "" {
					errMessage = fmt.Sprintf(errMessage, server.URL+"/page")
				}
				assert.ErrorContains(t, err, errMessage)
				assert.NotContains(t, err.Error(), "secret")
				assert.Nil(t, page)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, []*htmlForm{{action: "/x", inputs: []htmlInput{{name: "a"}}}}, page.forms)
		})
	}

	t.Run("read_body_error", func(t *testing.T) {
		t.Parallel()
		client, err := New(newReadErrorHTTPClient(), "", "", Credentials{}, Session{})
		require.NoError(t, err)

		page, err := client.doAuthRequest(t.Context(), http.MethodGet, "https://auth.purevpn.com", nil)

		assert.ErrorContains(t, err, "reading response body: test read error")
		assert.Nil(t, page)
	})
}
