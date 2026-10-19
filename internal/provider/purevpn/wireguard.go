package purevpn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/purevpn/wgapi"
	"github.com/qdm12/gluetun/internal/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// wireguardState is persisted to disk so restarts do not need
// to log in again or change the Wireguard key pair.
type wireguardState struct {
	PrivateKey string        `json:"private_key"`
	Session    wgapi.Session `json:"session"`
	// UsernameHash is the hash of the account username from the
	// settings the session belongs to, so the session of a previous
	// account is not used after changing the username.
	UsernameHash string `json:"username_hash,omitempty"`
	// SessionTokenHash is the hash of the session token from the
	// settings which was used to seed the session, so a changed
	// token in the settings replaces the stored session.
	SessionTokenHash string `json:"session_token_hash,omitempty"`
}

type wireguardFetcher struct {
	// network is used to reach PureVPN before the VPN is up.
	network   RestrictedNetwork
	statePath string
	// authURL and appURL are the PureVPN websites base URLs,
	// and are left empty to use the default ones.
	authURL string
	appURL  string

	state       wireguardState
	stateLoaded bool
}

func newWireguardFetcher(network RestrictedNetwork) *wireguardFetcher {
	return &wireguardFetcher{
		network:   network,
		statePath: "/gluetun/purevpn-wireguard.json",
	}
}

// FetchWireguardConnection logs in the PureVPN member area if needed,
// and requests a new Wireguard configuration. It should be called on
// every connection attempt, since PureVPN removes unused peers.
// It is not safe for concurrent use.
func (p *Provider) FetchWireguardConnection(ctx context.Context, vpnSettings settings.VPN,
	logger wireguard.Logger,
) (connection models.WireguardConnection, err error) {
	return p.wireguard.fetch(ctx, vpnSettings, logger)
}

func (f *wireguardFetcher) fetch(ctx context.Context,
	vpnSettings settings.VPN, logger Logger,
) (connection models.WireguardConnection, err error) {
	purevpnSettings := vpnSettings.PureVPN
	// The settings validation ensures there is exactly one known country.
	countryCode, _ := constants.CountryNameToCode(vpnSettings.Provider.ServerSelection.Countries[0])
	countryCode = strings.ToUpper(countryCode)

	// Bound the whole fetch so it does not block the VPN loop for too long,
	// for example preventing it from being stopped or its settings changed.
	const fetchTimeout = 2 * time.Minute
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	f.loadState(logger)

	privateKey, publicKey, err := f.keyPair(*vpnSettings.Wireguard.PrivateKey, logger)
	if err != nil {
		return models.WireguardConnection{}, err
	}
	f.applyAccount(*purevpnSettings.Username, *purevpnSettings.SessionToken, logger)

	transport := &restrictedTransport{network: f.network}
	defer func() {
		// Failing to remove a firewall rule is not fatal, for example
		// if the firewall got disabled during the fetch, removing all rules.
		cleanupErr := transport.cleanup()
		if cleanupErr != nil {
			logger.Warn("cleaning up connections to PureVPN: " + cleanupErr.Error())
		}
	}()
	const httpTimeout = 30 * time.Second
	httpClient := &http.Client{Transport: transport, Timeout: httpTimeout}

	credentials := wgapi.Credentials{
		Username:   *purevpnSettings.Username,
		Password:   *purevpnSettings.Password,
		TOTPSecret: *purevpnSettings.TOTPSecret,
	}
	client, err := wgapi.New(httpClient, f.authURL, f.appURL, credentials, f.state.Session)
	if err != nil {
		return models.WireguardConnection{}, fmt.Errorf("creating PureVPN client: %w", err)
	}

	location := describeLocation(countryCode, *purevpnSettings.CityID)
	logger.Info("fetching Wireguard configuration from PureVPN for " + location)
	config, err := client.FetchConfig(ctx, wgapi.ServerRequest{
		CountryCode:     countryCode,
		CityID:          *purevpnSettings.CityID,
		SubscriptionID:  *purevpnSettings.SubscriptionID,
		VPNUsername:     *purevpnSettings.VPNUsername,
		ClientPublicKey: publicKey,
	})
	f.state.Session = client.Session()
	f.saveState(logger) // save even on error, the session may have changed
	if err != nil {
		return models.WireguardConnection{}, fmt.Errorf("requesting configuration from PureVPN: %w", err)
	}

	endpointIP, ok := config.EndpointIP()
	if !ok {
		ips, err := f.network.ResolveName(ctx, config.EndpointHost)
		switch {
		case err != nil:
			return models.WireguardConnection{}, fmt.Errorf("resolving Wireguard endpoint: %w", err)
		case len(ips) == 0:
			return models.WireguardConnection{}, fmt.Errorf("no IP address found for Wireguard endpoint %s",
				config.EndpointHost)
		}
		endpointIP = ips[0]
	}

	logger.Info(fmt.Sprintf("PureVPN Wireguard server %s (%s:%d)",
		config.EndpointHost, endpointIP, config.EndpointPort))

	return models.WireguardConnection{
		Connection: models.Connection{
			Type:       vpn.Wireguard,
			IP:         endpointIP,
			Port:       config.EndpointPort,
			Protocol:   constants.UDP,
			Hostname:   config.EndpointHost,
			ServerName: config.EndpointHost,
			PubKey:     config.ServerPublicKey.String(),
		},
		PrivateKey:          privateKey,
		Addresses:           config.Addresses,
		PersistentKeepalive: config.PersistentKeepalive,
	}, nil
}

func describeLocation(countryCode string, cityID uint32) string {
	if cityID == 0 {
		return "country " + countryCode
	}
	return fmt.Sprintf("country %s city ID %d", countryCode, cityID)
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

// applyAccount discards the stored session if it belongs to another
// account than the one from the settings, and then seeds the session
// with the session token from the settings, which is the fusionauth.sso
// single sign-on cookie, if it is set and different from the one used
// last. When the username is unchanged, other authentication cookies,
// such as the two-factor trusted device cookie, are kept.
// A password change alone keeps the session, which stays valid for
// the same account.
func (f *wireguardFetcher) applyAccount(username, sessionToken string, logger Logger) {
	usernameHash := hashHex(username)
	if usernameHash != f.state.UsernameHash {
		// A missing username hash, for example for a new state or a state
		// written by an older program version, means the account of the
		// stored session is unknown, so the session is discarded to be safe.
		hasSession := f.state.Session.AccessToken != "" || len(f.state.Session.AuthCookies) > 0
		if hasSession {
			logger.Info("discarding the stored PureVPN session since it is not for the configured account")
		}
		f.state.Session = wgapi.Session{}
		f.state.SessionTokenHash = ""
		f.state.UsernameHash = usernameHash
	}

	if sessionToken == "" {
		return
	}
	tokenHash := hashHex(sessionToken)
	if tokenHash == f.state.SessionTokenHash {
		return // already applied, the stored session is more recent
	}

	logger.Debug("using PureVPN session token as single sign-on cookie")
	f.state.Session = f.state.Session.WithSessionToken(sessionToken)
	f.state.SessionTokenHash = tokenHash
}

func hashHex(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
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
	err = writeFileAtomically(f.statePath, data)
	if err != nil {
		logger.Warn("saving PureVPN state, the next restart will need to log in again: " + err.Error())
	}
}

// writeFileAtomically writes the data to a temporary file in the same
// directory as the file path given, syncs it, and renames it to the file
// path, so the file is never partially written. The file permissions
// are set to 0600, even if the file already existed.
func writeFileAtomically(path string, data []byte) (err error) {
	directory := filepath.Dir(path)
	const dirPerm = 0o700
	err = os.MkdirAll(directory, dirPerm)
	if err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	file, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}
	temporaryPath := file.Name()
	defer func() {
		if err != nil {
			_ = file.Close()
			_ = os.Remove(temporaryPath)
		}
	}()

	const filePerm = 0o600
	err = file.Chmod(filePerm)
	if err != nil {
		return fmt.Errorf("setting temporary file permissions: %w", err)
	}
	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("writing temporary file: %w", err)
	}
	err = file.Sync()
	if err != nil {
		return fmt.Errorf("syncing temporary file: %w", err)
	}
	err = file.Close()
	if err != nil {
		return fmt.Errorf("closing temporary file: %w", err)
	}
	err = os.Rename(temporaryPath, path)
	if err != nil {
		return fmt.Errorf("renaming temporary file: %w", err)
	}
	return nil
}
