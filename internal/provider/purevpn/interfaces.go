package purevpn

import (
	"context"
	"net/http"
	"net/netip"
)

// RestrictedNetwork reaches hosts before the VPN is up, through temporary
// firewall rules restricted to each connection.
type RestrictedNetwork interface {
	OpenHTTPSByHostname(ctx context.Context, hostname string) (
		httpClient *http.Client, cleanup func() error, err error)
	ResolveName(ctx context.Context, host string) (addresses []netip.Addr, err error)
}

type Logger interface {
	Debug(s string)
	Info(s string)
	Warn(s string)
}
