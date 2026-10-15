# PureVPN WireGuard

Gluetun can connect to PureVPN with WireGuard by generating the WireGuard
configuration from your PureVPN account, the same way the
[PureVPN member area](https://my.purevpn.com/v2/dashboard/manual-config) does.

⚠️ PureVPN has no official API for this. Gluetun uses the member area
endpoints, which PureVPN can change at any time without notice.

## Quick start

1. Fill in [`purevpn-wireguard.env`](../purevpn-wireguard.env) at the
   repository root. At minimum, set `PUREVPN_USERNAME`, `PUREVPN_PASSWORD`
   and `PUREVPN_COUNTRY`.
1. Run Gluetun with it, for example with Docker Compose:

    ```yaml
    services:
      gluetun:
        image: qmcgaw/gluetun
        cap_add:
          - NET_ADMIN
        devices:
          - /dev/net/tun:/dev/net/tun
        env_file: purevpn-wireguard.env
        volumes:
          - ./gluetun:/gluetun
    ```

Mount `/gluetun` as a volume. Gluetun keeps the WireGuard key pair and the
PureVPN login session in `/gluetun/purevpn-wireguard.json` (permissions
`0600`), so a restart does not need to log in again.

## Settings

| Variable | Default | Description |
| --- | --- | --- |
| `VPN_SERVICE_PROVIDER` | | `purevpn` |
| `VPN_TYPE` | | `wireguard` |
| `PUREVPN_USERNAME` | | PureVPN account email, the one you use on the website. It is not the `purevpn0s...` VPN username. |
| `PUREVPN_PASSWORD` | | PureVPN account password |
| `PUREVPN_TOTP_SECRET` | | Base32 secret of the authenticator app, only if two-factor authentication is enabled |
| `PUREVPN_SESSION_TOKEN` | | Session token from a browser, see [Session token](#session-token) |
| `PUREVPN_COUNTRY` | | Two-letter server country code, for example `US` |
| `PUREVPN_CITY_ID` | | PureVPN city ID, for example `8778` for New York. The list is at the bottom of `purevpn-wireguard.env`. If empty, PureVPN picks a city. |
| `PUREVPN_SUBSCRIPTION_ID` | | Subscription ID, only needed if the account has more than one subscription |
| `PUREVPN_VPN_USERNAME` | | VPN username (`purevpn0s...`), only needed if the subscription has more than one |
| `WIREGUARD_PRIVATE_KEY` | | Optional. If empty, Gluetun generates a key and keeps it. |

Set either the username and password, or a session token, or both. Every
secret can also be read from a file: `/run/secrets/purevpn_password`, or a
path set with `PUREVPN_PASSWORD_SECRETFILE`. The same works for
`PUREVPN_TOTP_SECRET` and `PUREVPN_SESSION_TOKEN`.

The `SERVER_*` filters are ignored: the server location comes from
`PUREVPN_COUNTRY` and `PUREVPN_CITY_ID`.

## Login and two-factor authentication

Gluetun logs in on its own the first time, and again whenever the stored
session stops working:

1. It reuses the stored access token if that token has not expired.
1. Otherwise, it uses the stored single sign-on session cookie
   (`fusionauth.sso`), which does not need the password.
1. Otherwise, it logs in with the username and password. If two-factor
   authentication is enabled, it generates the 6-digit code from
   `PUREVPN_TOTP_SECRET` and asks PureVPN to trust the device, so later
   logins can skip the code.

The TOTP secret is the text version of the QR code shown when you enable
two-factor authentication. It is often shown as "Can't scan the code?".
Only authenticator app two-factor authentication is supported; email or
SMS codes are not.

### Session token

If you do not want to give Gluetun your password or TOTP secret, log in
once in a browser instead:

1. Log in to [my.purevpn.com](https://my.purevpn.com), and check "keep me
   signed in" if it is offered.
1. Open the browser developer tools, then Application (Chrome) or Storage
   (Firefox), then Cookies, then `https://auth.purevpn.com`.
1. Copy the value of the `fusionauth.sso` cookie into
   `PUREVPN_SESSION_TOKEN`.

Gluetun stores and refreshes the session itself. When the session finally
expires, Gluetun falls back to the username and password if they are set.
Otherwise it stops with an error asking for a new token. You can also paste
the `fa_token` cookie of `my.purevpn.com`, but it expires after a short time.

## Kill switch

With the firewall enabled (the default), all traffic is blocked until the
VPN is up, including the PureVPN website. To fetch the configuration,
Gluetun briefly does the following:

1. It allows HTTPS to the Cloudflare and Google DNS over HTTPS servers,
   and resolves `auth.purevpn.com` and `my.purevpn.com` through them. The
   system DNS is not used.
1. It allows HTTPS to the resolved PureVPN IP addresses only, and its HTTP
   client refuses any other destination.
1. It fetches the configuration, then removes these firewall rules before
   the WireGuard tunnel starts.

Only Gluetun's own login requests go through this opening, and only for
these few seconds. Connected containers stay blocked.

## Reconnection

PureVPN removes WireGuard peers that are not used, so Gluetun requests a
new configuration on every connection attempt. This includes reconnects
after a failed health check. If PureVPN rejects the access token, Gluetun
logs in again once and retries.

## Errors

| Error | Meaning |
| --- | --- |
| `PureVPN rejected the account username or password` | Wrong credentials, shown with PureVPN's own message |
| `two-factor authentication is enabled ... but no TOTP secret is set` | Set `PUREVPN_TOTP_SECRET` or `PUREVPN_SESSION_TOKEN` |
| `PureVPN rejected the two-factor code` | Wrong TOTP secret, or the system clock is off |
| `PureVPN two-factor method is not supported` | The account uses email or SMS codes |
| `PureVPN requires a captcha to log in` | Too many logins: log in from a browser and use a session token |
| `PureVPN login session expired and ... not set` | The session token expired and no username and password are set |
| `request blocked by the PureVPN website protection` | Cloudflare blocked the request, usually because of the IP address reputation. Gluetun keeps retrying with growing delays. |
| `no active PureVPN subscription found` / `PureVPN subscription not found` | Check the subscription; the error lists the ones available |
| `unexpected response from PureVPN` | PureVPN probably changed its website, so please report it |

Errors about credentials, two-factor authentication or captcha end with
"fix the PureVPN settings": retrying with the same settings fails again.
Network errors and blocks are retried with growing delays.

## Testing your settings without Docker

To check your account settings against the real PureVPN website without
starting a VPN, run:

```sh
PUREVPN_LIVE_TEST="$PWD/purevpn-wireguard.env" \
  go test -count=1 -run Test_Live -v ./internal/provider/purevpn/wgapi/
```

It logs in, requests a configuration and prints it, without the private
key.
