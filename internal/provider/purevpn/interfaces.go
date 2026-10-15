package purevpn

import (
	"context"
	"net/netip"
)

// Firewall and Logger are type aliases of interface literals, and not
// defined types, so the FetchWireguardConnection method signature is
// identical to the one expected by the vpn package, which defines the
// same interface literals without importing this package.
type (
	// Firewall allows output traffic marked with the given mark
	// temporarily, to reach the PureVPN website before the VPN is up,
	// with the kill switch enabled.
	Firewall = interface {
		AllowOutputTemporarily(ctx context.Context, protocol string, mark uint32,
			addrPorts []netip.AddrPort) (revert func(ctx context.Context) error, err error)
	}
	// Logger logs messages about fetching the Wireguard configuration.
	Logger = interface {
		Debug(s string)
		Info(s string)
		Warn(s string)
	}
)
