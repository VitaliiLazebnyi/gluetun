package settings

import (
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gotree"
)

// PureVPN contains settings to fetch WireGuard configurations
// from the PureVPN member area, using the PureVPN account.
// It is only used with the PureVPN provider and Wireguard.
type PureVPN struct {
	// Username is the PureVPN account email address.
	// It cannot be nil in the internal state.
	Username *string `json:"username"`
	// Password is the PureVPN account password.
	// It cannot be nil in the internal state.
	Password *string `json:"password"`
	// TOTPSecret is the base32 secret of the authenticator app
	// two-factor authentication. It can be the empty string if
	// two-factor authentication is disabled.
	// It cannot be nil in the internal state.
	TOTPSecret *string `json:"totp_secret"`
	// SessionToken is the value of the fusionauth.sso cookie of
	// auth.purevpn.com, copied from a browser logged in the PureVPN
	// member area. It can be the empty string, and cannot be nil
	// in the internal state.
	SessionToken *string `json:"session_token"`
	// CityID is the PureVPN city ID of the server location, in the
	// country set with the server selection countries filter.
	// It can be 0 to let PureVPN pick a city in the country,
	// and cannot be nil in the internal state.
	CityID *uint32 `json:"city_id"`
	// SubscriptionID is the subscription ID to use if the account
	// has more than one subscription. It can be the empty string
	// to use the first active subscription.
	// It cannot be nil in the internal state.
	SubscriptionID *string `json:"subscription_id"`
	// VPNUsername is the VPN username (purevpn0sXXXXX) to use if
	// the subscription has more than one. It can be the empty
	// string to use the first one.
	// It cannot be nil in the internal state.
	VPNUsername *string `json:"vpn_username"`
}

func (p PureVPN) validate() (err error) {
	hasCredentials := *p.Username != "" && *p.Password != ""
	switch {
	case !hasCredentials && *p.SessionToken == "":
		return errors.New("PureVPN account username and password, or session token, are not set")
	case *p.Username != "" && *p.Password == "":
		return errors.New("PureVPN account password is not set")
	case *p.Username == "" && *p.Password != "":
		return errors.New("PureVPN account username is not set")
	}

	if *p.TOTPSecret != "" {
		secret := strings.ToUpper(strings.ReplaceAll(*p.TOTPSecret, " ", ""))
		_, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(secret, "="))
		if err != nil {
			return fmt.Errorf("TOTP secret is not valid base32: %w", err)
		}
	}

	return nil
}

func (p *PureVPN) copy() (copied PureVPN) {
	return PureVPN{
		Username:       gosettings.CopyPointer(p.Username),
		Password:       gosettings.CopyPointer(p.Password),
		TOTPSecret:     gosettings.CopyPointer(p.TOTPSecret),
		SessionToken:   gosettings.CopyPointer(p.SessionToken),
		CityID:         gosettings.CopyPointer(p.CityID),
		SubscriptionID: gosettings.CopyPointer(p.SubscriptionID),
		VPNUsername:    gosettings.CopyPointer(p.VPNUsername),
	}
}

func (p *PureVPN) overrideWith(other PureVPN) {
	p.Username = gosettings.OverrideWithPointer(p.Username, other.Username)
	p.Password = gosettings.OverrideWithPointer(p.Password, other.Password)
	p.TOTPSecret = gosettings.OverrideWithPointer(p.TOTPSecret, other.TOTPSecret)
	p.SessionToken = gosettings.OverrideWithPointer(p.SessionToken, other.SessionToken)
	p.CityID = gosettings.OverrideWithPointer(p.CityID, other.CityID)
	p.SubscriptionID = gosettings.OverrideWithPointer(p.SubscriptionID, other.SubscriptionID)
	p.VPNUsername = gosettings.OverrideWithPointer(p.VPNUsername, other.VPNUsername)
}

func (p *PureVPN) setDefaults() {
	p.Username = gosettings.DefaultPointer(p.Username, "")
	p.Password = gosettings.DefaultPointer(p.Password, "")
	p.TOTPSecret = gosettings.DefaultPointer(p.TOTPSecret, "")
	p.SessionToken = gosettings.DefaultPointer(p.SessionToken, "")
	p.CityID = gosettings.DefaultPointer(p.CityID, 0)
	p.SubscriptionID = gosettings.DefaultPointer(p.SubscriptionID, "")
	p.VPNUsername = gosettings.DefaultPointer(p.VPNUsername, "")
}

func (p PureVPN) String() string {
	return p.toLinesNode().String()
}

func (p PureVPN) toLinesNode() (node *gotree.Node) {
	node = gotree.New("PureVPN account settings:")
	if *p.Username != "" {
		node.Appendf("Username: %s", gosettings.ObfuscateKey(*p.Username))
		node.Appendf("Password: %s", gosettings.ObfuscateKey(*p.Password))
	}
	if *p.TOTPSecret != "" {
		node.Appendf("TOTP secret: %s", gosettings.ObfuscateKey(*p.TOTPSecret))
	}
	if *p.SessionToken != "" {
		node.Appendf("Session token: %s", gosettings.ObfuscateKey(*p.SessionToken))
	}
	if *p.CityID != 0 {
		node.Appendf("City ID: %d", *p.CityID)
	}
	if *p.SubscriptionID != "" {
		node.Appendf("Subscription ID: %s", *p.SubscriptionID)
	}
	if *p.VPNUsername != "" {
		node.Appendf("VPN username: %s", gosettings.ObfuscateKey(*p.VPNUsername))
	}
	return node
}

func (p *PureVPN) read(r *reader.Reader) (err error) {
	p.Username = r.Get("PUREVPN_USERNAME", reader.ForceLowercase(false))
	p.Password = r.Get("PUREVPN_PASSWORD", reader.ForceLowercase(false))
	p.TOTPSecret = r.Get("PUREVPN_TOTP_SECRET", reader.ForceLowercase(false))
	p.SessionToken = r.Get("PUREVPN_SESSION_TOKEN", reader.ForceLowercase(false))
	p.CityID, err = r.Uint32Ptr("PUREVPN_CITY_ID")
	if err != nil {
		return err
	}
	p.SubscriptionID = r.Get("PUREVPN_SUBSCRIPTION_ID", reader.ForceLowercase(false))
	p.VPNUsername = r.Get("PUREVPN_VPN_USERNAME", reader.ForceLowercase(false))
	return nil
}
