package vpn

import (
	"context"
	"net/netip"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
)

// wireguardConnectionFetcher is implemented by providers generating
// Wireguard configurations at runtime through their API.
type wireguardConnectionFetcher interface {
	FetchWireguardConnection(ctx context.Context, vpnSettings settings.VPN,
		fw wireguardFetcherFirewall, logger wireguardFetcherLogger,
	) (connection models.WireguardConnection, err error)
}

// wireguardFetcherFirewall and wireguardFetcherLogger are type aliases of
// interface literals, and not defined types, so the method signature of
// wireguardConnectionFetcher is identical to the one of providers defining
// the same interface literals, without this package importing them.
type (
	wireguardFetcherFirewall = interface {
		AllowOutputTemporarily(ctx context.Context, protocol string, mark uint32,
			addrPorts []netip.AddrPort) (revert func(ctx context.Context) error, err error)
	}
	wireguardFetcherLogger = interface {
		Debug(s string)
		Info(s string)
		Warn(s string)
	}
)
