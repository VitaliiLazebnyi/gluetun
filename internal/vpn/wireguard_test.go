package vpn

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/gluetun/internal/provider"
	"github.com/qdm12/gluetun/internal/provider/purevpn"
	"github.com/qdm12/gluetun/internal/wireguard"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

// The PureVPN provider must implement WireguardFetcher, or the
// type assertion in setupWireguard silently falls back to GetConnection.
var _ WireguardFetcher = (*purevpn.Provider)(nil)

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
		"user_and_provider_zero_keepalive": {
			fetched: models.WireguardConnection{
				Connection: serverConnection,
				PrivateKey: "fetched-private-key",
				Addresses:  []netip.Prefix{ipv4Address},
			},
			connection: serverConnection,
			privateKey: "fetched-private-key",
			addresses:  []netip.Prefix{ipv4Address},
			keepalive:  0,
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
			logger := NewMockLogger(ctrl)
			fetcher := NewMockWireguardFetcher(ctrl)
			fetcher.EXPECT().FetchWireguardConnection(ctx, vpnSettings, logger).
				Return(testCase.fetched, testCase.fetchErr)

			connection, wireguardSettings, err := fetchWireguardConnection(ctx,
				fetcher, vpnSettings, testCase.ipv6Supported, logger)

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

// fetcherProvider is a provider also implementing WireguardFetcher.
type fetcherProvider struct {
	provider.Provider // nil, since its methods are not called
	*MockWireguardFetcher
}

func Test_setupWireguard(t *testing.T) {
	t.Parallel()

	const privateKey = "Y0QnWR6mhgxOjNkPUkRdPYKYrB+pERhKFAuhkBapHw8="
	const publicKey = "aPxGwq8zERHQ3Q1cOZFdJ+cvJX5Ka4mLN38AyYKYF10="
	serverConnection := models.Connection{
		Type:   "wireguard",
		IP:     netip.MustParseAddr("198.51.100.9"),
		Port:   51820,
		PubKey: publicKey,
	}
	newVPNSettings := func(privateKey string, addresses []netip.Prefix) settings.VPN {
		return settings.VPN{
			Provider: settings.Provider{
				ServerSelection: settings.ServerSelection{VPN: "wireguard", Countries: []string{"Germany"}},
			},
			Wireguard: settings.Wireguard{
				PrivateKey:                  new(privateKey),
				PreSharedKey:                new(""),
				Addresses:                   addresses,
				PersistentKeepaliveInterval: new(time.Duration(0)),
				Interface:                   "wg0",
				Implementation:              "userspace",
				MTU:                         new(uint32(0)),
				GSO:                         new(false),
				AllowedIPs:                  []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			},
		}
	}
	// fetcherSettings are the settings used with a WireguardFetcher
	// provider, without private key nor interface addresses.
	fetcherSettings := newVPNSettings("", nil)
	// connectionSettings are the settings used with a provider
	// getting its connection from the servers data.
	connectionSettings := newVPNSettings(privateKey, []netip.Prefix{netip.MustParsePrefix("10.2.0.2/32")})
	errTest := errors.New("test error")

	testCases := map[string]struct {
		vpnSettings settings.VPN
		// buildProvider returns the provider with its mocked calls expected.
		buildProvider func(ctrl *gomock.Controller, ctx context.Context,
			logger wireguard.Logger) provider.Provider
		// connectionFound is true if the provider gives a connection,
		// so the keys are logged and the firewall is set.
		connectionFound bool
		firewallErr     error
		errMessage      string
	}{
		"fetcher_provider": {
			vpnSettings: fetcherSettings,
			buildProvider: func(ctrl *gomock.Controller, ctx context.Context,
				logger wireguard.Logger,
			) provider.Provider {
				fetcher := NewMockWireguardFetcher(ctrl)
				fetcher.EXPECT().FetchWireguardConnection(ctx, fetcherSettings, logger).
					Return(models.WireguardConnection{
						Connection: serverConnection,
						PrivateKey: privateKey,
						Addresses:  []netip.Prefix{netip.MustParsePrefix("172.21.7.9/32")},
					}, nil).Times(1)
				return fetcherProvider{MockWireguardFetcher: fetcher}
			},
			connectionFound: true,
		},
		"fetcher_provider_error": {
			vpnSettings: fetcherSettings,
			buildProvider: func(ctrl *gomock.Controller, ctx context.Context,
				logger wireguard.Logger,
			) provider.Provider {
				fetcher := NewMockWireguardFetcher(ctrl)
				fetcher.EXPECT().FetchWireguardConnection(ctx, fetcherSettings, logger).
					Return(models.WireguardConnection{}, errTest).Times(1)
				return fetcherProvider{MockWireguardFetcher: fetcher}
			},
			errMessage: "fetching Wireguard connection: test error",
		},
		"servers_data_provider": {
			vpnSettings: connectionSettings,
			buildProvider: func(ctrl *gomock.Controller, _ context.Context,
				_ wireguard.Logger,
			) provider.Provider {
				serversDataProvider := NewMockProvider(ctrl)
				serversDataProvider.EXPECT().GetConnection(connectionSettings.Provider.ServerSelection, false).
					Return(serverConnection, nil).Times(1)
				return serversDataProvider
			},
			connectionFound: true,
		},
		"servers_data_provider_error": {
			vpnSettings: connectionSettings,
			buildProvider: func(ctrl *gomock.Controller, _ context.Context,
				_ wireguard.Logger,
			) provider.Provider {
				serversDataProvider := NewMockProvider(ctrl)
				serversDataProvider.EXPECT().GetConnection(connectionSettings.Provider.ServerSelection, false).
					Return(models.Connection{}, errTest).Times(1)
				return serversDataProvider
			},
			errMessage: "finding a VPN server: test error",
		},
		"firewall_error": {
			vpnSettings: connectionSettings,
			buildProvider: func(ctrl *gomock.Controller, _ context.Context,
				_ wireguard.Logger,
			) provider.Provider {
				serversDataProvider := NewMockProvider(ctrl)
				serversDataProvider.EXPECT().GetConnection(connectionSettings.Provider.ServerSelection, false).
					Return(serverConnection, nil).Times(1)
				return serversDataProvider
			},
			connectionFound: true,
			firewallErr:     errTest,
			errMessage:      "setting firewall: test error",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			ctx := context.Background()
			firewall := NewMockFirewall(ctrl)
			logger := NewMockLogger(ctrl)
			vpnProvider := testCase.buildProvider(ctrl, ctx, logger)
			if testCase.connectionFound {
				logger.EXPECT().Debug("Wireguard server public key: " + publicKey).Times(1)
				logger.EXPECT().Debug("Wireguard client private key: Y0Q...w8=").Times(1)
				logger.EXPECT().Debug("Wireguard pre-shared key: [not set]").Times(1)
				firewall.EXPECT().SetVPNConnection(ctx, serverConnection, "wg0").
					Return(testCase.firewallErr).Times(1)
			}

			wireguarder, connection, err := setupWireguard(ctx, nil, firewall,
				vpnProvider, testCase.vpnSettings, netlink.IPv6Unsupported, logger)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
				assert.Nil(t, wireguarder)
				assert.Equal(t, models.Connection{}, connection)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, wireguarder)
			assert.Equal(t, serverConnection, connection)
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
