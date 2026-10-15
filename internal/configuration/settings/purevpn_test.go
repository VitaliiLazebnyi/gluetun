package settings

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/reader/sources/env"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
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
			errMessage: "PureVPN account username and password, or session token, are not set",
		},
		"password_missing": {
			settings:   PureVPN{Username: new("user@example.com"), SessionToken: new("token")},
			errMessage: "PureVPN account password is not set",
		},
		"username_missing": {
			settings:   PureVPN{Password: new("pass"), SessionToken: new("token")},
			errMessage: "PureVPN account username is not set",
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

func Test_Wireguard_validate_purevpn(t *testing.T) {
	t.Parallel()

	const validKey = "Y0QnWR6mhgxOjNkPUkRdPYKYrB+pERhKFAuhkBapHw8="
	testCases := map[string]struct {
		privateKey   string
		preSharedKey string
		addresses    []netip.Prefix
		errMessage   string
	}{
		"defaults":            {},
		"valid_private_key":   {privateKey: validKey},
		"invalid_private_key": {privateKey: "invalid", errMessage: "private key is not valid"},
		"preshared_key_set":   {preSharedKey: validKey, errMessage: "pre-shared key cannot be set for PureVPN"},
		"addresses_set": {
			addresses:  []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
			errMessage: "interface addresses cannot be set for PureVPN",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			wireguardSettings := Wireguard{
				PrivateKey:   new(testCase.privateKey),
				PreSharedKey: new(testCase.preSharedKey),
				Addresses:    testCase.addresses,
			}
			wireguardSettings.setDefaults(providers.Purevpn)

			const ipv6Supported, amneziawg = false, false
			err := wireguardSettings.validate(providers.Purevpn, ipv6Supported, amneziawg)

			if testCase.errMessage == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}

func Test_WireguardSelection_validate_purevpn(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		selection  WireguardSelection
		errMessage string
	}{
		"defaults": {},
		"endpoint_ip_set": {
			selection:  WireguardSelection{EndpointIP: netip.MustParseAddr("203.0.113.1")},
			errMessage: "endpoint IP cannot be set for PureVPN",
		},
		"endpoint_port_set": {selection: WireguardSelection{EndpointPort: new(uint16(51820))}, errMessage: "endpoint port"},
		"public_key_set": {
			selection:  WireguardSelection{PublicKey: "Y0QnWR6mhgxOjNkPUkRdPYKYrB+pERhKFAuhkBapHw8="},
			errMessage: "public key cannot be set for PureVPN",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			selection := testCase.selection
			selection.setDefaults()

			err := selection.validate(providers.Purevpn)

			if testCase.errMessage == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}

func Test_validatePureVPNWireguard(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		selection  ServerSelection
		warning    string
		errMessage string
	}{
		"no_country": {
			errMessage: "exactly one country must be set with PureVPN Wireguard, but got 0: ",
		},
		"two_countries": {
			selection:  ServerSelection{Countries: []string{"Germany", "France"}},
			errMessage: "exactly one country must be set with PureVPN Wireguard, but got 2: Germany, France",
		},
		"unknown_country": {
			selection:  ServerSelection{Countries: []string{"Atlantis"}},
			errMessage: `country code not found for country "Atlantis"`,
		},
		"country_only": {selection: ServerSelection{Countries: []string{"united kingdom"}}},
		"ignored_filters": {
			selection: ServerSelection{
				Countries: []string{"United States"}, Regions: []string{"region"},
				Cities: []string{"New York"}, ISPs: []string{"isp"}, Names: []string{"name"},
				Numbers: []uint16{1}, Hostnames: []string{"host"}, Categories: []string{"category"},
			},
			warning: "server selection filters regions, cities, ISPs, names, numbers, hostnames, " +
				"categories are ignored with PureVPN Wireguard, use PUREVPN_CITY_ID to select a city",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			warner := NewMockWarner(ctrl)
			if testCase.warning != "" {
				warner.EXPECT().Warn(testCase.warning)
			}

			err := validatePureVPNWireguard(testCase.selection, warner)

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
		CityID:         new(uint(1234)),
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
		CityID:         new(uint(1234)),
		SubscriptionID: new("Sub-1"),
		VPNUsername:    new("PureVPN0s123"),
	}
	assert.Equal(t, expected, settings)
}
