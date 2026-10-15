// Package wgapi implements a client for the undocumented PureVPN
// member area API used to generate WireGuard configurations.
// PureVPN does not provide an official API, so the endpoints and
// login flow were reverse engineered from https://my.purevpn.com
// and may change without notice.
package wgapi

import "errors"

var (
	// errCredentialsNotSet is returned when no session token is usable
	// and the account username or password is not set.
	errCredentialsNotSet = errors.New("PureVPN account username and password are not set")
	// errInvalidCredentials is returned when PureVPN rejects the
	// account username and password.
	errInvalidCredentials = errors.New("PureVPN rejected the account username or password")
	// errTwoFactorRequired is returned when the account has two-factor
	// authentication enabled and no TOTP secret is set.
	errTwoFactorRequired = errors.New("two-factor authentication is enabled on the PureVPN account " +
		"but no TOTP secret is set")
	// errTwoFactorCodeInvalid is returned when PureVPN rejects the
	// generated two-factor code.
	errTwoFactorCodeInvalid = errors.New("PureVPN rejected the two-factor code, " +
		"check the TOTP secret and the system clock")
	// errTwoFactorMethodUnsupported is returned when the account two-factor
	// method is not an authenticator app (for example email or SMS).
	errTwoFactorMethodUnsupported = errors.New("PureVPN two-factor method is not supported, " +
		"only authenticator app (TOTP) is supported")
	// errCaptchaRequired is returned when PureVPN requires a captcha
	// to log in, which cannot be solved automatically.
	errCaptchaRequired = errors.New("PureVPN requires a captcha to log in, " +
		"log in once from a browser or set a session token")
	// errBlocked is returned when the request is blocked by the PureVPN
	// website protection (Cloudflare).
	errBlocked = errors.New("request blocked by the PureVPN website protection")
	// errUnauthorized is returned when the API rejects the access token,
	// usually because it expired.
	errUnauthorized = errors.New("PureVPN API rejected the access token")
	// errSessionExpired is returned when the stored login session is no
	// longer accepted by PureVPN.
	errSessionExpired = errors.New("PureVPN login session expired")
	// errNoActiveSubscription is returned when the account has no
	// active subscription.
	errNoActiveSubscription = errors.New("no active PureVPN subscription found")
	// errSubscriptionNotFound is returned when the subscription ID or
	// VPN username set does not match any subscription of the account.
	errSubscriptionNotFound = errors.New("PureVPN subscription not found")
	// errAPI is returned when the API answers with an error status.
	errAPI = errors.New("PureVPN API error")
	// errHostNotAllowed is returned when a redirect or a form would send
	// a request to a host other than the PureVPN auth and app hosts.
	errHostNotAllowed = errors.New("host not allowed")
	// errUnexpectedResponse is returned when a response does not have
	// the expected format, usually because PureVPN changed its website.
	errUnexpectedResponse = errors.New("unexpected response from PureVPN")
)

// IsAuthError returns true if the error is due to the account
// credentials or login session, such that retrying without
// changing the settings is pointless.
func IsAuthError(err error) bool {
	for _, target := range [...]error{
		errCredentialsNotSet, errInvalidCredentials,
		errTwoFactorRequired, errTwoFactorCodeInvalid,
		errTwoFactorMethodUnsupported,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// IsCaptchaError returns true if the error is due to PureVPN
// requiring a captcha to log in, which may no longer be the
// case after some time without login attempts.
func IsCaptchaError(err error) bool {
	return errors.Is(err, errCaptchaRequired)
}
