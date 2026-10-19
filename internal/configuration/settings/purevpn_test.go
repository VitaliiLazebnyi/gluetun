package settings

import (
	"testing"

	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/reader/sources/env"
	"github.com/stretchr/testify/assert"
)

func Test_PureVPN_validate(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings   PureVPN
		errMessage string
	}{
		"credentials":        {settings: PureVPN{Username: new("user@example.com"), Password: new("pass")}},
		"session_token_only": {settings: PureVPN{SessionToken: new("token")}},
		"valid_TOTP_secret": {
			settings: PureVPN{SessionToken: new("token"), TOTPSecret: new("jbsw y3dp ehpk 3pxp")},
		},
		"nothing_set": {
			errMessage: "account username and password, or session token, are not set",
		},
		"password_missing": {
			settings:   PureVPN{Username: new("user@example.com"), SessionToken: new("token")},
			errMessage: "account password is not set",
		},
		"username_missing": {
			settings:   PureVPN{Password: new("pass"), SessionToken: new("token")},
			errMessage: "account username is not set",
		},
		"invalid_TOTP_secret": {
			settings:   PureVPN{SessionToken: new("token"), TOTPSecret: new("not-base32!")},
			errMessage: "TOTP secret is not valid base32: illegal base32 data at input byte 3",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			settings := testCase.settings
			settings.setDefaults()

			err := settings.validate()

			if testCase.errMessage == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}

func Test_PureVPN_toLinesNode(t *testing.T) {
	t.Parallel()

	settings := PureVPN{
		Username:       new("user@example.com"),
		Password:       new("password"),
		TOTPSecret:     new("JBSWY3DPEHPK3PXP"),
		SessionToken:   new("sessiontoken"),
		CityID:         new(uint32(1234)),
		SubscriptionID: new("sub-1"),
		VPNUsername:    new("purevpn0s123"),
	}
	settings.setDefaults()

	const expected = `PureVPN account settings:
├── Username: [set]
├── Password: [set]
├── TOTP secret: [set]
├── Session token: [set]
├── City ID: 1234
├── Subscription ID: sub-1
└── VPN username: [set]`
	assert.Equal(t, expected, settings.String())
}

func Test_PureVPN_read(t *testing.T) {
	t.Parallel()

	reader := reader.New(reader.Settings{
		Sources: []reader.Source{env.New(env.Settings{Environ: []string{
			"PUREVPN_USERNAME=User@Example.com",
			"PUREVPN_PASSWORD=PassWord",
			"PUREVPN_TOTP_SECRET=JBSWY3DPEHPK3PXP",
			"PUREVPN_SESSION_TOKEN=TokenValue",
			"PUREVPN_CITY_ID=1234",
			"PUREVPN_SUBSCRIPTION_ID=Sub-1",
			"PUREVPN_VPN_USERNAME=PureVPN0s123",
		}})},
	})

	var settings PureVPN
	err := settings.read(reader)

	assert.NoError(t, err)
	expected := PureVPN{
		Username:       new("User@Example.com"),
		Password:       new("PassWord"),
		TOTPSecret:     new("JBSWY3DPEHPK3PXP"),
		SessionToken:   new("TokenValue"),
		CityID:         new(uint32(1234)),
		SubscriptionID: new("Sub-1"),
		VPNUsername:    new("PureVPN0s123"),
	}
	assert.Equal(t, expected, settings)
}
