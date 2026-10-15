package models

import (
	"net/netip"
	"time"
)

// WireguardConnection is a Wireguard connection generated at runtime
// by a VPN provider, for example through its API.
type WireguardConnection struct {
	// Connection is the VPN server connection.
	Connection Connection
	// PrivateKey is the Wireguard client private key used.
	PrivateKey string
	// Addresses are the Wireguard interface addresses assigned.
	Addresses []netip.Prefix
	// PersistentKeepalive is the persistent keepalive interval
	// recommended by the provider, and can be zero.
	PersistentKeepalive time.Duration
}
