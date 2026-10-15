package vpn

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/purevpn"
	"github.com/qdm12/gluetun/internal/wireguard"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// The PureVPN provider must implement wireguardConnectionFetcher, or the
// type assertion in setupWireguard silently falls back to GetConnection.
var _ wireguardConnectionFetcher = (*purevpn.Provider)(nil)

func Test_fetchWireguardConnection(t *testing.T) {
	t.Parallel()

	serverConnection := models.Connection{
		Type:   "wireguard",
		IP:     netip.MustParseAddr("198.51.100.9"),
		Port:   51820,
		PubKey: "server-public-key",
	}
	ipv4Address := netip.MustParsePrefix("172.21.7.9/32")
	ipv6Address := netip.MustParsePrefix("fd00::9/128")

	testCases := map[string]struct {
		fetched        models.WireguardConnection
		fetchErr       error
		userPrivateKey string
		userAddresses  []netip.Prefix
		userKeepalive  time.Duration
		ipv6Supported  bool
		connection     models.Connection
		privateKey     string
		addresses      []netip.Prefix
		keepalive      time.Duration
		errMessage     string
	}{
		"fetch_error": {
			fetchErr:   errors.New("test error"),
			errMessage: "test error",
		},
		"overrides_and_provider_keepalive": {
			fetched: models.WireguardConnection{
				Connection:          serverConnection,
				PrivateKey:          "fetched-private-key",
				Addresses:           []netip.Prefix{ipv4Address},
				PersistentKeepalive: 21 * time.Second,
			},
			userPrivateKey: "",
			userAddresses:  []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
			connection:     serverConnection,
			privateKey:     "fetched-private-key",
			addresses:      []netip.Prefix{ipv4Address},
			keepalive:      21 * time.Second,
		},
		"user_keepalive_kept": {
			fetched: models.WireguardConnection{
				Connection:          serverConnection,
				PrivateKey:          "user-private-key",
				Addresses:           []netip.Prefix{ipv4Address, ipv6Address},
				PersistentKeepalive: 21 * time.Second,
			},
			userPrivateKey: "user-private-key",
			userKeepalive:  time.Minute,
			connection:     serverConnection,
			privateKey:     "user-private-key",
			addresses:      []netip.Prefix{ipv4Address, ipv6Address},
			keepalive:      time.Minute,
		},
		"no_address": {
			fetched: models.WireguardConnection{
				Connection: serverConnection,
				PrivateKey: "fetched-private-key",
			},
			errMessage: "no interface address assigned by the provider",
		},
		"ipv6_only_address_without_ipv6_support": {
			fetched: models.WireguardConnection{
				Connection: serverConnection,
				PrivateKey: "fetched-private-key",
				Addresses:  []netip.Prefix{ipv6Address},
			},
			errMessage: "no IPv4 interface address assigned by the provider in [fd00::9/128] " +
				"and IPv6 is not supported",
		},
		"ipv6_only_address_with_ipv6_support": {
			fetched: models.WireguardConnection{
				Connection: serverConnection,
				PrivateKey: "fetched-private-key",
				Addresses:  []netip.Prefix{ipv6Address},
			},
			ipv6Supported: true,
			connection:    serverConnection,
			privateKey:    "fetched-private-key",
			addresses:     []netip.Prefix{ipv6Address},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			vpnSettings := settings.VPN{
				Wireguard: settings.Wireguard{
					PrivateKey:                  new(testCase.userPrivateKey),
					Addresses:                   testCase.userAddresses,
					PersistentKeepaliveInterval: new(testCase.userKeepalive),
					Interface:                   "wg0",
				},
			}
			ctx := context.Background()
			firewall := NewMockwireguardFetcherFirewall(ctrl)
			logger := NewMockwireguardFetcherLogger(ctrl)
			fetcher := NewMockwireguardConnectionFetcher(ctrl)
			fetcher.EXPECT().FetchWireguardConnection(ctx, vpnSettings, firewall, logger).
				Return(testCase.fetched, testCase.fetchErr)

			connection, wireguardSettings, err := fetchWireguardConnection(ctx,
				fetcher, vpnSettings, firewall, testCase.ipv6Supported, logger)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, testCase.connection, connection)
			assert.Equal(t, testCase.privateKey, *wireguardSettings.PrivateKey)
			assert.Equal(t, testCase.addresses, wireguardSettings.Addresses)
			assert.Equal(t, testCase.keepalive, *wireguardSettings.PersistentKeepaliveInterval)
			assert.Equal(t, "wg0", wireguardSettings.Interface)
			// The user settings given must not be modified.
			assert.Equal(t, testCase.userPrivateKey, *vpnSettings.Wireguard.PrivateKey)
			assert.Equal(t, testCase.userKeepalive, *vpnSettings.Wireguard.PersistentKeepaliveInterval)
		})
	}
}

func Test_buildWireguardSettings(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		connection    models.Connection
		userSettings  settings.Wireguard
		ipv6Supported bool
		settings      wireguard.Settings
	}{
		"some_settings": {
			connection: models.Connection{
				IP:     netip.AddrFrom4([4]byte{1, 2, 3, 4}),
				Port:   51821,
				PubKey: "public",
			},
			userSettings: settings.Wireguard{
				PrivateKey:   ptrTo("private"),
				PreSharedKey: ptrTo("pre-shared"),
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 32),
					netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 32),
				},
				AllowedIPs: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
					netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 32),
				},
				PersistentKeepaliveInterval: ptrTo(time.Hour),
				Interface:                   "wg1",
				MTU:                         ptrTo(uint32(1000)),
				GSO:                         ptrTo(true),
			},
			ipv6Supported: false,
			settings: wireguard.Settings{
				InterfaceName: "wg1",
				PrivateKey:    "private",
				PublicKey:     "public",
				PreSharedKey:  "pre-shared",
				Endpoint:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 51821),
				Addresses: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 32),
				},
				AllowedIPs: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{2, 2, 2, 2}), 32),
				},
				PersistentKeepaliveInterval: time.Hour,
				RulePriority:                101,
				IPv6:                        ptrTo(false),
				MTU:                         1000,
				GSO:                         ptrTo(true),
			},
		},
		"gso_disabled": {
			connection: models.Connection{
				IP:     netip.AddrFrom4([4]byte{5, 6, 7, 8}),
				Port:   58820,
				PubKey: "public",
			},
			userSettings: settings.Wireguard{
				PrivateKey:                  ptrTo("private"),
				PreSharedKey:                ptrTo(""),
				PersistentKeepaliveInterval: ptrTo(time.Duration(0)),
				Interface:                   "wg0",
				MTU:                         ptrTo(uint32(0)),
				GSO:                         ptrTo(false),
			},
			ipv6Supported: false,
			settings: wireguard.Settings{
				InterfaceName: "wg0",
				PrivateKey:    "private",
				PublicKey:     "public",
				Endpoint:      netip.AddrPortFrom(netip.AddrFrom4([4]byte{5, 6, 7, 8}), 58820),
				Addresses:     []netip.Prefix{},
				AllowedIPs:    []netip.Prefix{},
				RulePriority:  101,
				IPv6:          ptrTo(false),
				MTU:           1320,
				GSO:           ptrTo(false),
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			settings := buildWireguardSettings(testCase.connection,
				testCase.userSettings, testCase.ipv6Supported)

			assert.Equal(t, testCase.settings, settings)
		})
	}
}
