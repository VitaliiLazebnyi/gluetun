package wgapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
