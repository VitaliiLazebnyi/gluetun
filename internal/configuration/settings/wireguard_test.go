package settings

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/providers"
	"github.com/stretchr/testify/assert"
)

func Test_Wireguard_validate(t *testing.T) {
	t.Parallel()

	const validKey = "Y0QnWR6mhgxOjNkPUkRdPYKYrB+pERhKFAuhkBapHw8="
	// 64 base64 characters decode to a 48 bytes key, which is
	// the size of a NordVPN access token.
	accessTokenSizedKey := strings.Repeat("A", 64)
	ipv4Addresses := []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}
	ipv6Addresses := []netip.Prefix{netip.MustParsePrefix("fd00::2/128")}

	testCases := map[string]struct {
		provider      string
		ipv6Supported bool
		privateKey    string
		preSharedKey  string
		addresses     []netip.Prefix
		errMessage    string
	}{
		"mullvad_valid": {
			provider:   providers.Mullvad,
			privateKey: validKey,
			addresses:  ipv4Addresses,
		},
		"mullvad_missing_private_key": {
			provider:   providers.Mullvad,
			addresses:  ipv4Addresses,
			errMessage: "private key is not set",
		},
		"mullvad_invalid_private_key": {
			provider:   providers.Mullvad,
			privateKey: "invalid",
			addresses:  ipv4Addresses,
			errMessage: "private key is not valid: wgtypes: failed to parse base64-encoded key",
		},
		"nordvpn_access_token_as_private_key": {
			provider:   providers.Nordvpn,
			privateKey: accessTokenSizedKey,
			errMessage: "private key is not valid: wgtypes: incorrect key size: 48",
		},
		"nordvpn_default_address": {
			provider:   providers.Nordvpn,
			privateKey: validKey,
		},
		"mullvad_missing_addresses": {
			provider:   providers.Mullvad,
			privateKey: validKey,
			errMessage: "interface address is not set",
		},
		"mullvad_ipv6_addresses_without_ipv6_support": {
			provider:   providers.Mullvad,
			privateKey: validKey,
			addresses:  ipv6Addresses,
			errMessage: "no IPv4 interface addresses in [fd00::2/128] but IPv6 is not supported",
		},
		"mullvad_ipv6_addresses_with_ipv6_support": {
			provider:      providers.Mullvad,
			ipv6Supported: true,
			privateKey:    validKey,
			addresses:     ipv6Addresses,
		},
		"mullvad_valid_pre_shared_key": {
			provider:     providers.Mullvad,
			privateKey:   validKey,
			preSharedKey: validKey,
			addresses:    ipv4Addresses,
		},
		"mullvad_invalid_pre_shared_key": {
			provider:     providers.Mullvad,
			privateKey:   validKey,
			preSharedKey: "invalid",
			addresses:    ipv4Addresses,
			errMessage:   "pre-shared key is not valid: wgtypes: failed to parse base64-encoded key",
		},
		"airvpn_missing_pre_shared_key": {
			provider:   providers.Airvpn,
			privateKey: validKey,
			addresses:  ipv4Addresses,
			errMessage: "pre-shared key is not set",
		},
		"airvpn_valid": {
			provider:     providers.Airvpn,
			privateKey:   validKey,
			preSharedKey: validKey,
			addresses:    ipv4Addresses,
		},
		"purevpn_defaults": {
			provider: providers.Purevpn,
		},
		"purevpn_valid_private_key": {
			provider:   providers.Purevpn,
			privateKey: validKey,
		},
		"purevpn_invalid_private_key": {
			provider:   providers.Purevpn,
			privateKey: "invalid",
			errMessage: "private key is not valid",
		},
		"purevpn_pre_shared_key_set": {
			provider:     providers.Purevpn,
			preSharedKey: validKey,
			errMessage:   "pre-shared key cannot be set for PureVPN",
		},
		"purevpn_invalid_pre_shared_key_set": {
			provider:     providers.Purevpn,
			preSharedKey: "invalid",
			errMessage:   "pre-shared key cannot be set for PureVPN",
		},
		"purevpn_addresses_set": {
			provider:   providers.Purevpn,
			addresses:  ipv4Addresses,
			errMessage: "interface addresses cannot be set for PureVPN",
		},
		"purevpn_ipv6_addresses_set": {
			provider:   providers.Purevpn,
			addresses:  ipv6Addresses,
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
			wireguardSettings.setDefaults(testCase.provider)

			const amneziawg = false
			err := wireguardSettings.validate(testCase.provider, testCase.ipv6Supported, amneziawg)

			if testCase.errMessage == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, testCase.errMessage)
		})
	}
}

func Test_Wireguard_toLinesNode(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		provider  string
		addresses []netip.Prefix
		expected  string
	}{
		"mullvad_with_addresses": {
			provider:  providers.Mullvad,
			addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")},
			expected: `Wireguard settings:
├── Interface addresses:
|   └── 10.0.0.2/32
├── Allowed IPs:
|   ├── 0.0.0.0/0
|   └── ::/0
└── Network interface: wg0
    └── MTU: use path MTU discovery`,
		},
		"purevpn_without_addresses": {
			provider: providers.Purevpn,
			expected: `Wireguard settings:
├── Allowed IPs:
|   ├── 0.0.0.0/0
|   └── ::/0
└── Network interface: wg0
    └── MTU: use path MTU discovery`,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			settings := Wireguard{Addresses: testCase.addresses}
			settings.setDefaults(testCase.provider)

			assert.Equal(t, testCase.expected, settings.String())
		})
	}
}
