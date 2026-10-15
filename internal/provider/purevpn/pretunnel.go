package purevpn

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"syscall"
	"time"

	dnsprovider "github.com/qdm12/dns/v2/pkg/provider"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/provider/purevpn/wgapi"
)

// newPreTunnelMark returns a random mark to set on sockets used before
// the VPN is up, so the temporary firewall rules only accept packets from
// these sockets, and not from other programs sharing the network namespace,
// such as containers using `network_mode: service:gluetun`.
// Setting a socket mark requires the CAP_NET_ADMIN capability or, since
// Linux 5.17, the CAP_NET_RAW capability which Docker grants by default,
// and reading the mark of another socket or the firewall rules requires
// the CAP_NET_ADMIN capability. The mark is therefore random and changes
// on each fetch, so a program with CAP_NET_RAW but without CAP_NET_ADMIN
// cannot guess it. It must differ from other marks used: 0x567 (kill switch
// connection mark), 4545 (TCP path MTU discovery) and 51820 (Wireguard).
func newPreTunnelMark() (mark uint32) {
	const killSwitchMark, pmtudMark, wireguardMark = 0x567, 4545, 51820
	for mark == 0 || mark == killSwitchMark || mark == pmtudMark || mark == wireguardMark {
		var buffer [4]byte
		_, _ = rand.Read(buffer[:]) // never returns an error
		mark = binary.BigEndian.Uint32(buffer[:])
	}
	return mark
}

type dohServer struct {
	// url is the DNS over HTTPS URL, for example
	// "https://cloudflare-dns.com/dns-query".
	url string
	// ips are the IPv4 addresses of the server hostname,
	// dialed instead of resolving the hostname.
	ips []netip.Addr
}

type preTunnelSettings struct {
	// dohServers are the DNS over HTTPS servers used to resolve hosts.
	dohServers []dohServer
	// hosts are the hostnames to resolve and allow to reach.
	hosts []string
	// port is the TCP port to reach on the hosts.
	port uint16
	// mark is the mark the firewall rules require packets to have,
	// and which dialControl should set on each socket.
	mark uint32
	// dialControl is run on each socket before it connects.
	dialControl func(network, address string, rawConn syscall.RawConn) error
	// rootCAs are the root certificate authorities to verify TLS
	// certificates with, and nil to use the system ones.
	rootCAs *x509.CertPool
}

func defaultPreTunnelSettings() preTunnelSettings {
	upstreams := [...]dnsprovider.Provider{dnsprovider.Cloudflare(), dnsprovider.Google()}
	dohServers := make([]dohServer, len(upstreams))
	for i, upstream := range upstreams {
		dohServers[i] = dohServer{url: upstream.DoH.URL, ips: upstream.DoH.IPv4}
	}
	const https = 443
	mark := newPreTunnelMark()
	return preTunnelSettings{
		dohServers:  dohServers,
		hosts:       []string{mustHost(wgapi.DefaultAuthURL), mustHost(wgapi.DefaultAppURL)},
		port:        https,
		mark:        mark,
		dialControl: newMarkControl(mark),
	}
}

func mustHost(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return parsedURL.Hostname()
}

// newPreTunnelHTTPClient returns an HTTP client able to reach the
// PureVPN website before the VPN is up, even with the firewall enabled.
// It temporarily allows HTTPS traffic from marked sockets to DNS over
// HTTPS servers, resolves the PureVPN hostnames with them, and then
// allows HTTPS traffic from marked sockets to the resolved IP addresses.
// All connections use marked sockets, dial pinned IP addresses only, and
// do not depend on the system DNS nor on a proxy. The cleanup function
// returned closes idle connections and removes the firewall rules, logging
// any error.
func newPreTunnelHTTPClient(ctx context.Context, fw Firewall, logger Logger,
	preTunnel preTunnelSettings,
) (client *http.Client, resolve func(ctx context.Context, host string) ([]netip.Addr, error),
	cleanup func(), err error,
) {
	const dialTimeout = 10 * time.Second
	dialer := &net.Dialer{Timeout: dialTimeout, Control: preTunnel.dialControl}

	var transports []*http.Transport
	var reverts []func(ctx context.Context) error
	cleanup = func() {
		for _, transport := range transports {
			transport.CloseIdleConnections()
		}
		for _, revert := range slices.Backward(reverts) {
			err := revert(context.Background())
			if err != nil {
				logger.Warn("removing temporary firewall rules: " + err.Error())
			}
		}
	}

	dohAddresses := make(map[string][]netip.AddrPort, len(preTunnel.dohServers))
	dohURLs := make([]string, len(preTunnel.dohServers))
	var dohAddrPorts []netip.AddrPort
	for i, server := range preTunnel.dohServers {
		hostPort, port, err := urlHostPort(server.url)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parsing DNS over HTTPS URL: %w", err)
		}
		dohURLs[i] = server.url
		for _, ip := range server.ips {
			addrPort := netip.AddrPortFrom(ip, port)
			dohAddresses[hostPort] = append(dohAddresses[hostPort], addrPort)
			dohAddrPorts = append(dohAddrPorts, addrPort)
		}
	}

	revert, err := fw.AllowOutputTemporarily(ctx, constants.TCP, preTunnel.mark, dohAddrPorts)
	reverts = append(reverts, revert)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("allowing DNS over HTTPS traffic: %w", err)
	}

	dohTransport := newPinnedTransport(dialer, dohAddresses, preTunnel.rootCAs)
	transports = append(transports, dohTransport)
	const dohTimeout = 5 * time.Second
	resolver := &dohResolver{
		client: &http.Client{Transport: dohTransport, Timeout: dohTimeout},
		urls:   dohURLs,
	}
	resolve = resolver.lookupIPv4

	hostAddresses := make(map[string][]netip.AddrPort, len(preTunnel.hosts))
	var allowed []netip.AddrPort
	for _, host := range preTunnel.hosts {
		ips, err := resolve(ctx, host)
		if err != nil {
			cleanup()
			return nil, nil, nil, fmt.Errorf("resolving %s: %w", host, err)
		}
		hostPort := net.JoinHostPort(host, strconv.Itoa(int(preTunnel.port)))
		for _, ip := range ips {
			addrPort := netip.AddrPortFrom(ip, preTunnel.port)
			hostAddresses[hostPort] = append(hostAddresses[hostPort], addrPort)
			allowed = append(allowed, addrPort)
		}
	}

	revert, err = fw.AllowOutputTemporarily(ctx, constants.TCP, preTunnel.mark, allowed)
	reverts = append(reverts, revert)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("allowing traffic to PureVPN website: %w", err)
	}

	transport := newPinnedTransport(dialer, hostAddresses, preTunnel.rootCAs)
	transports = append(transports, transport)
	const httpTimeout = 30 * time.Second
	client = &http.Client{Transport: transport, Timeout: httpTimeout}
	return client, resolve, cleanup, nil
}

// urlHostPort returns the "host:port" address and the port
// of the URL given, defaulting to port 443.
func urlHostPort(rawURL string) (hostPort string, port uint16, err error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", 0, err
	}
	const https = 443
	port = https
	if parsedURL.Port() != "" {
		const base, bitSize = 10, 16
		port64, err := strconv.ParseUint(parsedURL.Port(), base, bitSize)
		if err != nil {
			return "", 0, fmt.Errorf("parsing port: %w", err)
		}
		port = uint16(port64)
	}
	hostPort = net.JoinHostPort(parsedURL.Hostname(), strconv.Itoa(int(port)))
	return hostPort, port, nil
}

// newPinnedTransport returns an HTTP transport only dialing "host:port"
// addresses present in the addresses map given, using their pinned IP
// addresses and ports instead of resolving the host, and refusing any
// other address. It never uses a proxy.
func newPinnedTransport(dialer *net.Dialer, addresses map[string][]netip.AddrPort,
	rootCAs *x509.CertPool,
) *http.Transport {
	const tlsHandshakeTimeout = 10 * time.Second
	const maxIdleConns = 4
	return &http.Transport{
		Proxy: nil, // connections must only go to the pinned addresses
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			addrPorts, ok := addresses[address]
			if !ok {
				// Refuse other destinations, they are blocked by the firewall anyway.
				return nil, fmt.Errorf("destination %s is not allowed before the VPN is up", address)
			}
			errs := make([]error, 0, len(addrPorts))
			for _, addrPort := range addrPorts {
				conn, err := dialer.DialContext(ctx, network, addrPort.String())
				if err == nil {
					return conn, nil
				}
				errs = append(errs, err)
			}
			return nil, errors.Join(errs...)
		},
		TLSClientConfig: &tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: tlsHandshakeTimeout,
		MaxIdleConns:        maxIdleConns,
	}
}
