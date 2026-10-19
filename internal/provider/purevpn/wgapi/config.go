package wgapi

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Config is the Wireguard configuration returned by PureVPN.
// The client private key is not part of it, since PureVPN
// returns a {clientPrivateKey} placeholder in its place.
type Config struct {
	// Addresses are the interface addresses assigned to the client.
	Addresses []netip.Prefix
	// ServerPublicKey is the Wireguard public key of the server.
	ServerPublicKey wgtypes.Key
	// EndpointHost is the server endpoint host, either an IP
	// address or a hostname.
	EndpointHost string
	// EndpointPort is the server endpoint UDP port.
	EndpointPort uint16
	// PersistentKeepalive is the persistent keepalive interval,
	// and is zero if not set.
	PersistentKeepalive time.Duration
	// ProtocolIP is the server IP address, given separately
	// from the configuration, and is invalid if not given.
	ProtocolIP netip.Addr
}

// EndpointIP returns the protocol IP if it is set, or else the
// endpoint host if it is an IP address.
func (c Config) EndpointIP() (ip netip.Addr, ok bool) {
	if c.ProtocolIP.IsValid() {
		return c.ProtocolIP, true
	}
	ip, err := netip.ParseAddr(c.EndpointHost)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

var (
	errAddressMissing   = errors.New("interface address is missing")
	errPublicKeyMissing = errors.New("peer public key is missing")
	errEndpointMissing  = errors.New("peer endpoint is missing")
)

// parseConfig parses a wg-quick style Wireguard configuration.
func parseConfig(content string) (config Config, err error) {
	section := ""
	for line := range strings.Lines(content) {
		line = strings.TrimSpace(line)
		commentIndex := strings.IndexAny(line, "#;")
		if commentIndex >= 0 {
			line = strings.TrimSpace(line[:commentIndex])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)

		switch section + "." + key {
		case "interface.address":
			config.Addresses, err = parseAddresses(value)
		case "peer.publickey":
			config.ServerPublicKey, err = wgtypes.ParseKey(value)
		case "peer.endpoint":
			config.EndpointHost, config.EndpointPort, err = parseEndpoint(value)
		case "peer.persistentkeepalive":
			var seconds uint64
			seconds, err = strconv.ParseUint(value, 10, 16)
			config.PersistentKeepalive = time.Duration(seconds) * time.Second
		}
		if err != nil {
			return Config{}, fmt.Errorf("parsing %s %s: %w", section, key, err)
		}
	}

	switch {
	case len(config.Addresses) == 0:
		return Config{}, errAddressMissing
	case config.ServerPublicKey == wgtypes.Key{}:
		return Config{}, errPublicKeyMissing
	case config.EndpointHost == "":
		return Config{}, errEndpointMissing
	}
	return config, nil
}

func parseAddresses(value string) (addresses []netip.Prefix, err error) {
	for field := range strings.SplitSeq(value, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if !strings.Contains(field, "/") {
			addr, err := netip.ParseAddr(field)
			if err != nil {
				return nil, fmt.Errorf("parsing address: %w", err)
			}
			addresses = append(addresses, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(field)
		if err != nil {
			return nil, fmt.Errorf("parsing prefix: %w", err)
		}
		addresses = append(addresses, prefix)
	}
	return addresses, nil
}

func parseEndpoint(value string) (host string, port uint16, err error) {
	host, portString, err := net.SplitHostPort(value)
	if err != nil {
		return "", 0, fmt.Errorf("splitting host and port: %w", err)
	}
	port64, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("parsing port: %w", err)
	}
	return host, uint16(port64), nil
}
