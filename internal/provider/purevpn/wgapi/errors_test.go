package wgapi

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_IsAuthError_IsCaptchaError(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		err          error
		authError    bool
		captchaError bool
	}{
		"nil":                     {},
		"other_error":             {err: errors.New("test")},
		"blocked":                 {err: errBlocked},
		"unexpected_response":     {err: errUnexpectedResponse},
		"credentials_not_set":     {err: errCredentialsNotSet, authError: true},
		"invalid_credentials":     {err: fmt.Errorf("x: %w", errInvalidCredentials), authError: true},
		"two_factor_required":     {err: errTwoFactorRequired, authError: true},
		"two_factor_code_invalid": {err: errTwoFactorCodeInvalid, authError: true},
		"two_factor_unsupported":  {err: errTwoFactorMethodUnsupported, authError: true},
		"captcha_required":        {err: fmt.Errorf("x: %w", errCaptchaRequired), captchaError: true},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, testCase.authError, IsAuthError(testCase.err))
			assert.Equal(t, testCase.captchaError, IsCaptchaError(testCase.err))
		})
	}
}
