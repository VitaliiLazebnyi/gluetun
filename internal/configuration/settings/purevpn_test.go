package settings

import (
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/stretchr/testify/assert"
)

func Test_PureVPN_validate(t *testing.T) {
	t.Parallel()

	makeSettings := func(username, password, totp, token, country string) PureVPN {
		s := PureVPN{
			Username: &username, Password: &password,
			TOTPSecret: &totp, SessionToken: &token, Country: country,
		}
		s.setDefaults()
		return s
	}

	testCases := map[string]struct {
		settings   PureVPN
		errMessage string
	}{
		"credentials": {
			settings: makeSettings("user@example.com", "pass", "", "", "US"),
		},
		"session_token_only": {
			settings: makeSettings("", "", "", "token", "gb"),
		},
		"valid_TOTP_secret": {
			settings: makeSettings("user@example.com", "pass", "jbsw y3dp ehpk 3pxp", "", "US"),
		},
		"nothing_set": {
			settings:   makeSettings("", "", "", "", "US"),
			errMessage: "PureVPN account username and password, or session token, are not set",
		},
		"password_missing": {
			settings:   makeSettings("user@example.com", "", "", "token", "US"),
			errMessage: "PureVPN account password is not set",
		},
		"username_missing": {
			settings:   makeSettings("", "pass", "", "", "US"),
			errMessage: "PureVPN account username and password, or session token, are not set",
		},
		"invalid_TOTP_secret": {
			settings:   makeSettings("user@example.com", "pass", "not-base32!", "", "US"),
			errMessage: "TOTP secret is not valid base32: illegal base32 data at input byte 3",
		},
		"country_missing": {
			settings:   makeSettings("user@example.com", "pass", "", "", ""),
			errMessage: `country is not a valid 2 letters country code: ""`,
		},
		"country_invalid": {
			settings:   makeSettings("user@example.com", "pass", "", "", "USA"),
			errMessage: `country is not a valid 2 letters country code: "USA"`,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := testCase.settings.validate()
			if testCase.errMessage == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}

func Test_Wireguard_validate_purevpn(t *testing.T) {
	t.Parallel()

	w := Wireguard{}
	w.setDefaults(providers.Purevpn)

	// Private key and addresses are fetched at runtime for PureVPN.
	err := w.validate(providers.Purevpn, false, false)
	assert.NoError(t, err)

	err = w.validate(providers.Mullvad, false, false)
	assert.ErrorContains(t, err, "private key is not set")

	invalidKey := "invalid"
	w.PrivateKey = &invalidKey
	err = w.validate(providers.Purevpn, false, false)
	assert.ErrorContains(t, err, "private key is not valid")
}
