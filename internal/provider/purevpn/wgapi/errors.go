// Package wgapi implements a client for the undocumented PureVPN
// member area API used to generate Wireguard configurations.
// PureVPN does not provide an official API, so the endpoints and
// login flow were reverse engineered from https://my.purevpn.com
// and may change without notice.
package wgapi

import "errors"

var (
	// errBlocked is returned when the request is blocked by the PureVPN
	// website protection (Cloudflare).
	errBlocked = errors.New("request blocked by the PureVPN website protection")
	// errUnauthorized is returned when the API rejects the access token,
	// usually because it expired.
	errUnauthorized = errors.New("PureVPN API rejected the access token")
)
