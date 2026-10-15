package settings

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/reader/sources/env"
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

	const validKey = "Y0QnWR6mhgxOjNkPUkRdPYKYrB+pERhKFAuhkBapHw8="
	testCases := map[string]struct {
		provider      string
		privateKey    string
		preSharedKey  string
		addresses     []netip.Prefix
		ipv6Supported bool
		errMessage    string
	}{
		"purevpn_defaults": {
			provider: providers.Purevpn,
		},
		"purevpn_preshared_key_set": {
			provider:     providers.Purevpn,
			preSharedKey: validKey,
			errMessage: "pre-shared key cannot be set for PureVPN, " +
				"since PureVPN Wireguard servers do not use one",
		},
		"other_provider_preshared_key_set": {
			provider:     providers.Mullvad,
			privateKey:   validKey,
			preSharedKey: validKey,
			addresses:    []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
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
		"other_provider_addresses_missing": {
			provider:   providers.Mullvad,
			privateKey: validKey,
			errMessage: "interface address is not set",
		},
		"other_provider_ipv6_only_not_supported": {
			provider:   providers.Mullvad,
			privateKey: validKey,
			addresses:  []netip.Prefix{netip.MustParsePrefix("fd00::2/128")},
			errMessage: "no IPv4 interface addresses in [fd00::2/128] but IPv6 is not supported",
		},
		"other_provider_ipv6_only_supported": {
			provider:      providers.Mullvad,
			privateKey:    validKey,
			addresses:     []netip.Prefix{netip.MustParsePrefix("fd00::2/128")},
			ipv6Supported: true,
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
				PrivateKey:   new(testCase.privateKey),
				PreSharedKey: new(testCase.preSharedKey),
				Addresses:    testCase.addresses,
			}
			wireguardSettings.setDefaults(testCase.provider)

			// Private key and addresses are fetched at runtime for PureVPN.
			err := wireguardSettings.validate(testCase.provider, testCase.ipv6Supported, false)

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
		provider        string
		selection       WireguardSelection
		clearEndpointIP bool
		errMessage      string
	}{
		"defaults": {},
		"endpoint_ip_zero_value": {
			clearEndpointIP: true,
		},
		"other_provider_public_key_set": {
			provider:  providers.Mullvad,
			selection: WireguardSelection{PublicKey: "Y0QnWR6mhgxOjNkPUkRdPYKYrB+pERhKFAuhkBapHw8="},
		},
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
			if testCase.clearEndpointIP {
				selection.EndpointIP = netip.Addr{}
			}

			provider := testCase.provider
			if provider == "" {
				provider = providers.Purevpn
			}

			err := selection.validate(provider)

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

func Test_warnPureVPNWireguardFilters_allFilters(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)

	warner := NewMockWarner(ctrl)
	warner.EXPECT().Warn("server selection filters ISPs, categories, cities, countries, hostnames, " +
		"names, numbers, regions are ignored with PureVPN Wireguard, " +
		"use PUREVPN_COUNTRY and PUREVPN_CITY_ID instead")
	selection := ServerSelection{
		Countries:  []string{"United States"},
		Regions:    []string{"New York"},
		Cities:     []string{"New York"},
		ISPs:       []string{"isp"},
		Names:      []string{"name"},
		Numbers:    []uint16{1},
		Hostnames:  []string{"us2-auto-udp.ptoserver.com"},
		Categories: []string{"category"},
	}

	warnPureVPNWireguardFilters(selection, warner)
}

func Test_validatePreSharedKey(t *testing.T) {
	t.Parallel()

	const validKey = "Y0QnWR6mhgxOjNkPUkRdPYKYrB+pERhKFAuhkBapHw8="
	testCases := map[string]struct {
		provider     string
		preSharedKey string
		errMessage   string
	}{
		"airvpn_missing": {
			provider:   providers.Airvpn,
			errMessage: "pre-shared key is not set",
		},
		"airvpn_valid": {
			provider:     providers.Airvpn,
			preSharedKey: validKey,
		},
		"purevpn_set": {
			provider:     providers.Purevpn,
			preSharedKey: validKey,
			errMessage: "pre-shared key cannot be set for PureVPN, " +
				"since PureVPN Wireguard servers do not use one",
		},
		"purevpn_empty": {
			provider: providers.Purevpn,
		},
		"optional_empty": {
			provider: providers.Mullvad,
		},
		"invalid": {
			provider:     providers.Mullvad,
			preSharedKey: "invalid",
			errMessage:   "pre-shared key is not valid: ",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := validatePreSharedKey(testCase.provider, testCase.preSharedKey)

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

	testCases := map[string]struct {
		settings PureVPN
		expected string
	}{
		"minimal": {
			settings: PureVPN{SessionToken: new("sessiontoken"), Country: "us"},
			expected: `PureVPN account settings:
├── Session token: [set]
└── Location: US`,
		},
		"credentials_only": {
			settings: PureVPN{Username: new("user@example.com"), Password: new("password"), Country: "US"},
			expected: `PureVPN account settings:
├── Username: user@example.com
├── Password: [set]
└── Location: US`,
		},
		"all_set": {
			settings: PureVPN{
				Username:       new("user@example.com"),
				Password:       new("password"),
				TOTPSecret:     new("JBSWY3DPEHPK3PXP"),
				SessionToken:   new("sessiontoken"),
				Country:        "gb",
				CityID:         new(uint(1234)),
				SubscriptionID: new("sub-1"),
				VPNUsername:    new("purevpn0s123"),
			},
			expected: `PureVPN account settings:
├── Username: user@example.com
├── Password: [set]
├── TOTP secret: [set]
├── Session token: [set]
├── Location: GB city ID 1234
├── Subscription ID: sub-1
└── VPN username: purevpn0s123`,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			settings := testCase.settings
			settings.setDefaults()

			assert.Equal(t, testCase.expected, settings.String())
		})
	}
}

func Test_PureVPN_read(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		environ    []string
		expected   PureVPN
		errMessage string
	}{
		"nothing_set": {},
		"all_set": {
			environ: []string{
				"PUREVPN_USERNAME=User@Example.com",
				"PUREVPN_PASSWORD=PassWord",
				"PUREVPN_TOTP_SECRET=JBSWY3DPEHPK3PXP",
				"PUREVPN_SESSION_TOKEN=TokenValue",
				"PUREVPN_COUNTRY=us",
				"PUREVPN_CITY_ID=1234",
				"PUREVPN_SUBSCRIPTION_ID=Sub-1",
				"PUREVPN_VPN_USERNAME=PureVPN0s123",
			},
			expected: PureVPN{
				Username:       new("User@Example.com"),
				Password:       new("PassWord"),
				TOTPSecret:     new("JBSWY3DPEHPK3PXP"),
				SessionToken:   new("TokenValue"),
				Country:        "US",
				CityID:         new(uint(1234)),
				SubscriptionID: new("Sub-1"),
				VPNUsername:    new("PureVPN0s123"),
			},
		},
		"invalid_city_id": {
			environ:    []string{"PUREVPN_COUNTRY=us", "PUREVPN_CITY_ID=abc"},
			expected:   PureVPN{Country: "US"},
			errMessage: "environment variable PUREVPN_CITY_ID: ",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			reader := reader.New(reader.Settings{
				Sources: []reader.Source{env.New(env.Settings{Environ: testCase.environ})},
			})

			var settings PureVPN
			err := settings.read(reader)

			if testCase.errMessage == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, testCase.errMessage)
			}
			assert.Equal(t, testCase.expected, settings)
		})
	}
}

func Test_VPN_purevpn(t *testing.T) {
	t.Parallel()

	makeSettings := func(pureVPN PureVPN) VPN {
		settings := VPN{
			Type:     vpn.Wireguard,
			Provider: Provider{Name: providers.Purevpn},
			PureVPN:  pureVPN,
		}
		settings.setDefaults()
		return settings
	}

	t.Run("validate_valid", func(t *testing.T) {
		t.Parallel()
		settings := makeSettings(PureVPN{SessionToken: new("token"), Country: "US"})
		err := settings.Validate(pureVPNFilterChoicesGetter{}, false, nil)
		assert.NoError(t, err)
	})

	t.Run("validate_invalid_purevpn_settings", func(t *testing.T) {
		t.Parallel()
		settings := makeSettings(PureVPN{SessionToken: new("token")})
		err := settings.Validate(pureVPNFilterChoicesGetter{}, false, nil)
		assert.EqualError(t, err, `PureVPN settings: country is not a valid 2 letters country code: ""`)
	})

	t.Run("validate_other_provider_ignores_purevpn_settings", func(t *testing.T) {
		t.Parallel()
		settings := VPN{
			Type:     vpn.Wireguard,
			Provider: Provider{Name: providers.Mullvad},
			Wireguard: Wireguard{
				PrivateKey: new("Y0QnWR6mhgxOjNkPUkRdPYKYrB+pERhKFAuhkBapHw8="),
				Addresses:  []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
			},
		}
		settings.setDefaults()
		err := settings.Validate(noopFilterChoicesGetter{}, false, nil)
		assert.NoError(t, err)
	})

	t.Run("to_lines_node", func(t *testing.T) {
		t.Parallel()
		settings := makeSettings(PureVPN{SessionToken: new("token"), Country: "US"})
		assert.Contains(t, settings.String(), "PureVPN account settings:")
		settings.Provider.Name = providers.Mullvad
		assert.NotContains(t, settings.String(), "PureVPN account settings:")
	})

	t.Run("read_success", func(t *testing.T) {
		t.Parallel()
		reader := reader.New(reader.Settings{
			Sources: []reader.Source{env.New(env.Settings{Environ: []string{"PUREVPN_COUNTRY=gb"}})},
		})
		var settings VPN
		err := settings.read(reader)
		assert.NoError(t, err)
		assert.Equal(t, "GB", settings.PureVPN.Country)
	})

	t.Run("read_error", func(t *testing.T) {
		t.Parallel()
		reader := reader.New(reader.Settings{
			Sources: []reader.Source{env.New(env.Settings{Environ: []string{"PUREVPN_CITY_ID=abc"}})},
		})
		var settings VPN
		err := settings.read(reader)
		assert.ErrorContains(t, err, "PureVPN: environment variable PUREVPN_CITY_ID: ")
	})
}
