package settings

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func Test_PureVPN_validate(t *testing.T) {
	t.Parallel()

	makeSettings := func(username, password, totp, token, country string) PureVPN {
		pureVPNSettings := PureVPN{
			Username: &username, Password: &password,
			TOTPSecret: &totp, SessionToken: &token, Country: country,
		}
		pureVPNSettings.setDefaults()
		return pureVPNSettings
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
		"password_only_without_session_token": {
			settings:   makeSettings("", "pass", "", "", "US"),
			errMessage: "PureVPN account username and password, or session token, are not set",
		},
		"username_missing_with_session_token": {
			settings:   makeSettings("", "pass", "", "token", "US"),
			errMessage: "PureVPN account username is not set",
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

	testCases := map[string]struct {
		provider   string
		privateKey string
		addresses  []netip.Prefix
		errMessage string
	}{
		"purevpn_defaults": {
			provider: providers.Purevpn,
		},
		"other_provider_private_key_missing": {
			provider:   providers.Mullvad,
			errMessage: "private key is not set",
		},
		"purevpn_invalid_private_key": {
			provider:   providers.Purevpn,
			privateKey: "invalid",
			errMessage: "private key is not valid",
		},
		"purevpn_addresses_set": {
			provider:  providers.Purevpn,
			addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
			errMessage: "interface addresses cannot be set for PureVPN, " +
				"since they are assigned by PureVPN: [10.0.0.2/32]",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			wireguardSettings := Wireguard{
				PrivateKey: &testCase.privateKey,
				Addresses:  testCase.addresses,
			}
			wireguardSettings.setDefaults(testCase.provider)

			// Private key and addresses are fetched at runtime for PureVPN.
			err := wireguardSettings.validate(testCase.provider, false, false)

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
		"endpoint_port_set": {
			selection:  WireguardSelection{EndpointPort: new(uint16(51820))},
			errMessage: "endpoint port cannot be set for PureVPN",
		},
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

type pureVPNFilterChoicesGetter struct{}

func (pureVPNFilterChoicesGetter) GetFilterChoices(string) models.FilterChoices {
	return models.FilterChoices{
		Countries: []string{"United States"},
		Cities:    []string{"New York"},
		Hostnames: []string{"us2-auto-udp.ptoserver.com"},
	}
}

func Test_ServerSelection_validate_purevpnWireguardFilters(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		vpnType   string
		countries []string
		cities    []string
		hostnames []string
		warning   string
	}{
		"wireguard_no_filter": {
			vpnType: vpn.Wireguard,
		},
		"wireguard_filters": {
			vpnType:   vpn.Wireguard,
			countries: []string{"United States"},
			cities:    []string{"New York"},
			hostnames: []string{"us2-auto-udp.ptoserver.com"},
			warning: "server selection filters cities, countries, hostnames are ignored " +
				"with PureVPN Wireguard, use PUREVPN_COUNTRY and PUREVPN_CITY_ID instead",
		},
		"openvpn_filters": {
			vpnType:   vpn.OpenVPN,
			countries: []string{"United States"},
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
			selection := ServerSelection{
				VPN:       testCase.vpnType,
				Countries: testCase.countries,
				Cities:    testCase.cities,
				Hostnames: testCase.hostnames,
			}
			selection.setDefaults(providers.Purevpn, false)

			err := selection.validate(providers.Purevpn, pureVPNFilterChoicesGetter{}, warner)

			assert.NoError(t, err)
		})
	}
}
