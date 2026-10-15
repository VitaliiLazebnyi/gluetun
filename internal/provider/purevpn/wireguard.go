package purevpn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/qdm12/dns/v2/pkg/doh"
	dnsprovider "github.com/qdm12/dns/v2/pkg/provider"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/purevpn/wgapi"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WireguardConnection is a Wireguard connection fetched from PureVPN.
type WireguardConnection struct {
	Connection          models.Connection
	PrivateKey          string
	Addresses           []netip.Prefix
	PersistentKeepalive time.Duration
}

const defaultWireguardStatePath = "/gluetun/purevpn-wireguard.json"

// wireguardState is persisted to disk so restarts do not need
// to log in again or change the Wireguard key pair.
type wireguardState struct {
	PrivateKey string        `json:"private_key"`
	Session    wgapi.Session `json:"session"`
	// SessionTokenHash is the hash of the session token from the
	// settings which was used to seed the session, so a changed
	// token in the settings replaces the stored session.
	SessionTokenHash string `json:"session_token_hash,omitempty"`
}

type wireguardFetcher struct {
	statePath string
	authURL   string
	appURL    string
	// newHTTPClient creates an HTTP client able to reach the PureVPN
	// website, and returns a function to call once done with it.
	newHTTPClient func(ctx context.Context, fw Firewall) (client *http.Client,
		resolve func(ctx context.Context, host string) ([]netip.Addr, error),
		cleanup func(), err error)

	mutex       sync.Mutex
	state       wireguardState
	stateLoaded bool
}

func newWireguardFetcher() *wireguardFetcher {
	return &wireguardFetcher{
		statePath:     defaultWireguardStatePath,
		newHTTPClient: newPreTunnelHTTPClient,
	}
}

// FetchWireguardConnection logs in the PureVPN member area if needed,
// and requests a new Wireguard configuration. It should be called on
// every connection attempt, since PureVPN removes unused peers.
func (p *Provider) FetchWireguardConnection(ctx context.Context,
	vpnSettings settings.VPN, fw Firewall, logger Logger,
) (connection WireguardConnection, err error) {
	return p.wireguard.fetch(ctx, vpnSettings, fw, logger)
}

func (f *wireguardFetcher) fetch(ctx context.Context,
	vpnSettings settings.VPN, fw Firewall, logger Logger,
) (connection WireguardConnection, err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	purevpnSettings := vpnSettings.PureVPN
	f.loadState(logger)

	privateKey, publicKey, err := f.keyPair(*vpnSettings.Wireguard.PrivateKey, logger)
	if err != nil {
		return WireguardConnection{}, err
	}
	f.applySessionToken(*purevpnSettings.SessionToken, logger)

	httpClient, resolve, cleanup, err := f.newHTTPClient(ctx, fw)
	if err != nil {
		return WireguardConnection{}, fmt.Errorf("preparing network access to PureVPN: %w", err)
	}
	defer cleanup()

	credentials := wgapi.Credentials{
		Username:   *purevpnSettings.Username,
		Password:   *purevpnSettings.Password,
		TOTPSecret: *purevpnSettings.TOTPSecret,
	}
	client, err := wgapi.New(httpClient, f.authURL, f.appURL, credentials, f.state.Session)
	if err != nil {
		return WireguardConnection{}, fmt.Errorf("creating PureVPN client: %w", err)
	}

	logger.Info("fetching Wireguard configuration from PureVPN for " + describeLocation(purevpnSettings))
	config, err := client.FetchConfig(ctx, wgapi.ServerRequest{
		CountryCode:     purevpnSettings.Country,
		CityID:          *purevpnSettings.CityID,
		SubscriptionID:  *purevpnSettings.SubscriptionID,
		VPNUsername:     *purevpnSettings.VPNUsername,
		ClientPublicKey: publicKey,
	})
	f.state.Session = client.Session()
	f.saveState(logger) // save even on error, the session may have changed
	if err != nil {
		if wgapi.IsAuthError(err) {
			err = fmt.Errorf("%w - fix the PureVPN settings, retrying with the same settings "+
				"will fail again", err)
		}
		return WireguardConnection{}, fmt.Errorf("fetching Wireguard configuration from PureVPN: %w", err)
	}

	endpointIP, ok := config.EndpointIP()
	if !ok {
		ips, err := resolve(ctx, config.EndpointHost)
		if err != nil {
			return WireguardConnection{}, fmt.Errorf("resolving Wireguard endpoint: %w", err)
		}
		endpointIP = ips[0]
	}

	logger.Info(fmt.Sprintf("PureVPN Wireguard server %s (%s:%d)",
		config.EndpointHost, endpointIP, config.EndpointPort))

	return WireguardConnection{
		Connection: models.Connection{
			Type:       vpn.Wireguard,
			IP:         endpointIP,
			Port:       config.EndpointPort,
			Protocol:   constants.UDP,
			Hostname:   config.EndpointHost,
			ServerName: config.EndpointHost,
			PubKey:     config.ServerPublicKey,
		},
		PrivateKey:          privateKey,
		Addresses:           config.Addresses,
		PersistentKeepalive: config.PersistentKeepalive,
	}, nil
}

func describeLocation(purevpnSettings settings.PureVPN) string {
	if *purevpnSettings.CityID == 0 {
		return "country " + purevpnSettings.Country
	}
	return fmt.Sprintf("country %s city ID %d", purevpnSettings.Country, *purevpnSettings.CityID)
}

// keyPair returns the private key from the settings if set, or the
// persisted private key, generating and persisting one if needed.
func (f *wireguardFetcher) keyPair(settingsKey string, logger Logger) (
	privateKey, publicKey string, err error,
) {
	privateKey = settingsKey
	if privateKey == "" {
		if f.state.PrivateKey == "" {
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return "", "", fmt.Errorf("generating Wireguard private key: %w", err)
			}
			f.state.PrivateKey = key.String()
			logger.Info("generated a new Wireguard key pair for PureVPN")
			f.saveState(logger)
		}
		privateKey = f.state.PrivateKey
	}

	key, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("parsing Wireguard private key: %w", err)
	}
	return privateKey, key.PublicKey().String(), nil
}

// applySessionToken seeds the session with the session token from
// the settings, if it is set and different from the one used last.
func (f *wireguardFetcher) applySessionToken(token string, logger Logger) {
	if token == "" {
		return
	}
	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])
	if tokenHash == f.state.SessionTokenHash {
		return // already applied, the stored session is more recent
	}

	if wgapi.IsJWT(token) {
		logger.Debug("using PureVPN session token as access token")
		f.state.Session = wgapi.Session{AccessToken: token}
	} else {
		logger.Debug("using PureVPN session token as single sign-on cookie")
		f.state.Session = wgapi.Session{
			AuthCookies: map[string]string{"fusionauth.sso": token},
		}
	}
	f.state.SessionTokenHash = tokenHash
}

func (f *wireguardFetcher) loadState(logger Logger) {
	if f.stateLoaded {
		return
	}
	f.stateLoaded = true

	data, err := os.ReadFile(f.statePath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return
	case err != nil:
		logger.Warn("reading PureVPN state file: " + err.Error())
		return
	}
	err = json.Unmarshal(data, &f.state)
	if err != nil {
		logger.Warn("decoding PureVPN state file, ignoring it: " + err.Error())
		f.state = wireguardState{}
	}
}

func (f *wireguardFetcher) saveState(logger Logger) {
	// The private key and session are persisted on purpose, in a 0600 file.
	data, err := json.MarshalIndent(f.state, "", "  ") //nolint:gosec
	if err != nil {
		logger.Warn("encoding PureVPN state: " + err.Error())
		return
	}
	const dirPerm, filePerm = 0o700, 0o600
	err = os.MkdirAll(filepath.Dir(f.statePath), dirPerm)
	if err == nil {
		err = os.WriteFile(f.statePath, data, filePerm)
	}
	if err != nil {
		logger.Warn("saving PureVPN state, the next restart will need to log in again: " + err.Error())
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
// It temporarily allows HTTPS traffic to DNS over HTTPS servers, resolves
// the PureVPN hostnames with them, and then allows HTTPS traffic to the
// resolved IP addresses only. The HTTP client dials these IP addresses
// directly, so it does not depend on the system DNS. The cleanup function
// returned removes the firewall rules and closes idle connections.
func newPreTunnelHTTPClient(ctx context.Context, fw Firewall) (client *http.Client,
	resolve func(ctx context.Context, host string) ([]netip.Addr, error),
	cleanup func(), err error,
) {
	upstreams := []dnsprovider.Provider{dnsprovider.Cloudflare(), dnsprovider.Google()}
	dohDialer, err := doh.New(doh.Settings{UpstreamResolvers: upstreams})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating DNS over HTTPS dialer: %w", err)
	}
	resolver := &net.Resolver{PreferGo: true, Dial: dohDialer.Dial}

	const https = 443
	var reverts []func(ctx context.Context) error
	cleanup = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) //nolint:mnd
		defer cancel()
		for _, revert := range slices.Backward(reverts) {
			_ = revert(ctx)
		}
		if client != nil {
			client.CloseIdleConnections()
		}
	}

	dohAddrPorts := make([]netip.AddrPort, 0)
	for _, upstream := range upstreams {
		for _, ip := range upstream.DoH.IPv4 {
			dohAddrPorts = append(dohAddrPorts, netip.AddrPortFrom(ip, https))
		}
	}
	revert, err := fw.AllowOutputTemporarily(ctx, constants.TCP, dohAddrPorts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("allowing DNS over HTTPS traffic: %w", err)
	}
	reverts = append(reverts, revert)

	resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
		ips, err := resolver.LookupNetIP(ctx, "ip4", host)
		switch {
		case err != nil:
			return nil, fmt.Errorf("resolving with DNS over HTTPS: %w", err)
		case len(ips) == 0:
			return nil, fmt.Errorf("no IPv4 address found for %s", host)
		}
		for i := range ips {
			ips[i] = ips[i].Unmap()
		}
		return ips, nil
	}

	purevpnHosts := [...]string{mustHost(wgapi.DefaultAuthURL), mustHost(wgapi.DefaultAppURL)}
	hostToIPs := make(map[string][]netip.Addr, len(purevpnHosts))
	var allowed []netip.AddrPort
	for _, host := range purevpnHosts {
		ips, err := resolve(ctx, host)
		if err != nil {
			cleanup()
			return nil, nil, nil, err
		}
		hostToIPs[host] = ips
		for _, ip := range ips {
			allowed = append(allowed, netip.AddrPortFrom(ip, https))
		}
	}
	revert, err = fw.AllowOutputTemporarily(ctx, constants.TCP, allowed)
	if err != nil {
		cleanup()
		return nil, nil, nil, fmt.Errorf("allowing traffic to PureVPN website: %w", err)
	}
	reverts = append(reverts, revert)

	dialer := &net.Dialer{Timeout: 10 * time.Second} //nolint:mnd
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, ok := hostToIPs[host]
			if !ok || port != strconv.Itoa(https) {
				// Refuse other destinations, they are blocked by the firewall anyway.
				return nil, fmt.Errorf("destination %s is not allowed before the VPN is up", address)
			}
			var errs []error
			for _, ip := range ips {
				conn, err := dialer.DialContext(ctx, network, netip.AddrPortFrom(ip, https).String())
				if err == nil {
					return conn, nil
				}
				errs = append(errs, err)
			}
			return nil, errors.Join(errs...)
		},
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second, //nolint:mnd
		MaxIdleConns:        4,                //nolint:mnd
	}
	client = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second, //nolint:mnd
	}
	return client, resolve, cleanup, nil
}
