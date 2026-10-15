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
	"sync"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider/purevpn/wgapi"
	"github.com/qdm12/gluetun/internal/restrictednet"
	"github.com/qdm12/gluetun/internal/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

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
	// authURL and appURL are the PureVPN websites base URLs,
	// and are left empty to use the default ones.
	authURL string
	appURL  string
	timeNow func() time.Time

	mutex       sync.Mutex
	state       wireguardState
	stateLoaded bool
	// authErr is the last authentication error, returned again without
	// contacting PureVPN as long as the PureVPN settings fingerprint is
	// authErrFingerprint and, if set, until authErrUntil, to avoid having
	// the account locked out or requiring a captcha because of repeated
	// failed logins.
	authErr            error
	authErrFingerprint string
	authErrUntil       time.Time
}

func newWireguardFetcher() *wireguardFetcher {
	return &wireguardFetcher{
		statePath: "/gluetun/purevpn-wireguard.json",
		timeNow:   time.Now,
	}
}

// FetchWireguardConnection logs in the PureVPN member area if needed,
// and requests a new Wireguard configuration. It should be called on
// every connection attempt, since PureVPN removes unused peers.
// The restricted network given is used to reach PureVPN before the VPN is up.
func (p *Provider) FetchWireguardConnection(ctx context.Context, vpnSettings settings.VPN,
	network *restrictednet.Client, logger wireguard.Logger,
) (connection models.WireguardConnection, err error) {
	return p.wireguard.fetch(ctx, vpnSettings, network, logger)
}

func (f *wireguardFetcher) fetch(ctx context.Context,
	vpnSettings settings.VPN, network RestrictedNetwork, logger Logger,
) (connection models.WireguardConnection, err error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	purevpnSettings := vpnSettings.PureVPN
	// The settings validation ensures there is exactly one known country.
	countryCode, _ := constants.CountryNameToCode(vpnSettings.Provider.ServerSelection.Countries[0])
	countryCode = strings.ToUpper(countryCode)
	fingerprint := settingsFingerprint(purevpnSettings, countryCode)
	if f.authErr != nil {
		if fingerprint == f.authErrFingerprint &&
			(f.authErrUntil.IsZero() || f.timeNow().Before(f.authErrUntil)) {
			return models.WireguardConnection{}, fmt.Errorf(
				"not retrying with unchanged PureVPN settings: %w", f.authErr)
		}
		f.authErr = nil
		f.authErrFingerprint = ""
		f.authErrUntil = time.Time{}
	}

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
	f.applySessionToken(*purevpnSettings.SessionToken, logger)

	transport := &restrictedTransport{network: network}
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
		err = fmt.Errorf("requesting configuration from PureVPN: %w", err)
		switch {
		case wgapi.IsCaptchaError(err):
			// The captcha may no longer be required after some time without login attempts.
			const captchaCooldown = time.Hour
			f.authErrUntil = f.timeNow().Add(captchaCooldown)
			err = fmt.Errorf("%w - not contacting PureVPN again before %s, unless the PureVPN settings change",
				err, f.authErrUntil.Format(time.RFC3339))
			f.authErr = err
			f.authErrFingerprint = fingerprint
		case wgapi.IsAuthError(err):
			err = fmt.Errorf("%w - change the PureVPN settings to retry, through the control "+
				"server or by restarting with fixed settings", err)
			f.authErr = err
			f.authErrFingerprint = fingerprint
		}
		return models.WireguardConnection{}, err
	}

	endpointIP, ok := config.EndpointIP()
	if !ok {
		ips, err := network.ResolveName(ctx, config.EndpointHost)
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

// settingsFingerprint returns a hash of the PureVPN settings, to detect
// a change in the settings without keeping the secrets in memory twice.
func settingsFingerprint(purevpnSettings settings.PureVPN, countryCode string) string {
	fields := [...]string{
		*purevpnSettings.Username,
		*purevpnSettings.Password,
		*purevpnSettings.TOTPSecret,
		*purevpnSettings.SessionToken,
		countryCode,
		fmt.Sprint(*purevpnSettings.CityID),
		*purevpnSettings.SubscriptionID,
		*purevpnSettings.VPNUsername,
	}
	hash := sha256.Sum256([]byte(strings.Join(fields[:], "\x00")))
	return hex.EncodeToString(hash[:])
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

// applySessionToken seeds the session with the session token from
// the settings, if it is set and different from the one used last.
// Other authentication cookies, such as the two-factor trusted device
// cookie, are kept.
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
	} else {
		logger.Debug("using PureVPN session token as single sign-on cookie")
	}
	f.state.Session = f.state.Session.WithSessionToken(token)
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
