package purevpn

import (
	"context"
	"net/netip"
)

// Firewall allows output traffic temporarily, to reach the PureVPN
// website before the VPN is up, with the kill switch enabled.
type Firewall interface {
	AllowOutputTemporarily(ctx context.Context, protocol string,
		addrPorts []netip.AddrPort) (revert func(ctx context.Context) error, err error)
}

// Logger logs messages about fetching the Wireguard configuration.
type Logger interface {
	Debug(s string)
	Info(s string)
	Warn(s string)
}
