# PureVPN WireGuard

Gluetun can connect to PureVPN with WireGuard by generating the WireGuard
configuration from your PureVPN account, the same way the
[PureVPN member area](https://my.purevpn.com/v2/dashboard/manual-config) does.

⚠️ PureVPN has no official API for this. Gluetun uses the member area
endpoints, which PureVPN can change at any time without notice.

## Quick start

1. Create an env file, for example `purevpn-wireguard.env`. Keep it out of
   version control, since it contains your credentials:

    ```sh
    VPN_SERVICE_PROVIDER=purevpn
    VPN_TYPE=wireguard
    PUREVPN_USERNAME=you@example.com
    PUREVPN_PASSWORD=your-account-password
    # Only if two-factor authentication is enabled:
    # PUREVPN_TOTP_SECRET=JBSWY3DPEHPK3PXP
    PUREVPN_COUNTRY=US
    # Optional, see the city IDs below. Empty lets PureVPN pick a city.
    PUREVPN_CITY_ID=8778
    ```

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
PureVPN login session in `/gluetun/purevpn-wireguard.json`, so a restart
does not need to log in again. The file is always written with permissions
`0600`, and atomically (written to a temporary file, then renamed), so it is
never left half written.

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
| `PUREVPN_CITY_ID` | | PureVPN city ID, for example `8778` for New York, see [City IDs](#city-ids). If empty, PureVPN picks a city. |
| `PUREVPN_SUBSCRIPTION_ID` | | Subscription ID, only needed if the account has more than one subscription |
| `PUREVPN_VPN_USERNAME` | | VPN username (`purevpn0s...`), only needed if the subscription has more than one |
| `WIREGUARD_PRIVATE_KEY` | | Optional. If empty, Gluetun generates a key and keeps it. |

Set either the username and password, or a session token, or both. Every
secret can also be read from a file: `/run/secrets/purevpn_password`, or a
path set with `PUREVPN_PASSWORD_SECRETFILE`. The same works for
`PUREVPN_TOTP_SECRET` (`/run/secrets/purevpn_totp_secret`) and
`PUREVPN_SESSION_TOKEN` (`/run/secrets/purevpn_session_token`).

PureVPN assigns the server endpoint, its public key and the interface
addresses, and its servers use no pre-shared key, so these settings are
rejected at startup: `WIREGUARD_ADDRESSES`, `WIREGUARD_ENDPOINT_IP`,
`WIREGUARD_ENDPOINT_PORT`, `WIREGUARD_PUBLIC_KEY` and
`WIREGUARD_PRESHARED_KEY`. If PureVPN assigns no IPv4 address and IPv6 is
not supported, the connection attempt fails.

The server location only comes from `PUREVPN_COUNTRY` and
`PUREVPN_CITY_ID`. The `SERVER_*` filters (countries, regions, cities,
hostnames...) are still validated at startup against Gluetun's PureVPN
OpenVPN server data, so an invalid value such as `SERVER_COUNTRIES=Atlantis`
fails at startup. Valid filters are then ignored, with a warning.

### City IDs

Snapshot of the PureVPN WireGuard locations from August 2025. PureVPN may
add, remove or renumber cities.

| Code | Country | Cities |
| --- | --- | --- |
| `US` | United States | Miami=7040, Phoenix=7190, Los Angeles=7344, Chicago=7904, Newark=8643, New York=8778, Houston=9259, Atlanta=16158, Washington DC=25099, Ashburn=26001, San Francisco=26002, Seattle=26021, Salt Lake City=26024 |
| `GB` | United Kingdom | London=3147, Manchester=4218 |
| `AU` | Australia | Sydney=65, Perth=72 |
| `DE` | Germany | Frankfurt=2762 |
| `CA` | Canada | Toronto=22 |
| `NL` | Netherlands | Amsterdam=2902 |
| `HK` | Hong Kong (SAR) | Hong Kong=4300 |
| `BE` | Belgium | Brussels=173 |
| `FR` | France | Paris=2753 |
| `SE` | Sweden | Stockholm=3005 |
| `JP` | Japan | Tokyo=993 |
| `SG` | Singapore | Singapore=5459 |
| `IT` | Italy | Milano=3124 |
| `IE` | Ireland | Dublin=713 |
| `LU` | Luxembourg | Luxembourg=2864 |
| `IN` | India | Mumbai=2797 |
| `AT` | Austria | Vienna=2387 |
| `DK` | Denmark | Copenhagen=5197 |
| `NO` | Norway | Oslo=2917 |
| `RO` | Romania | Bucharest=1290 |
| `RU` | Russia | Moscow=96 |
| `PL` | Poland | Warsaw=3431 |
| `CZ` | Czech Republic | Prague=370 |
| `FI` | Finland | Helsinki=2748 |
| `ES` | Spain | Madrid=530 |
| `CH` | Switzerland | Zurich=3021 |
| `LV` | Latvia | Riga=1044 |
| `TR` | Turkey | Istanbul=1385 |
| `LT` | Lithuania | Vilnius=2863 |
| `GR` | Greece | Athens=666 |
| `EE` | Estonia | Tallinn=2746 |
| `BG` | Bulgaria | Sofia=189 |
| `SK` | Slovakia | Bratislava=1539 |
| `BR` | Brazil | Sao Paulo=44 |
| `ZA` | South Africa | Johannesburg=2946 |
| `HU` | Hungary | Budapest=701 |
| `KR` | South Korea | Seoul=4865 |
| `NG` | Nigeria | Lagos=1145 |
| `MD` | Moldova | Chisinau=1047 |
| `AL` | Albania | Tirana=2335 |
| `CN` | China | Beijing=265 |
| `VN` | Vietnam | Hanoi=3062 |
| `AF` | Afghanistan | Kabul=2334 |
| `DZ` | Algeria | Algiers=2336 |
| `AO` | Angola | Benguela=6228 |
| `AR` | Argentina | Buenos Aires=4091 |
| `AW` | Aruba | Oranjestad=2355 |
| `BS` | Bahamas | Freeport=1506 |
| `BH` | Bahrain | Manama=3196 |
| `BD` | Bangladesh | Dhaka=2389 |
| `BB` | Barbados | Bridgetown=3299 |
| `BM` | Bermuda | Hamilton=2395 |
| `BO` | Bolivia | Sucre=1574 |
| `VG` | British Virgin Islands | Road Town=6463 |
| `BN` | Brunei Darussalam | Bandar Seri Begawan=1548 |
| `KY` | Cayman Islands | George Town=2420 |
| `CL` | Chile | Santiago=256 |
| `EG` | Egypt | Cairo=513 |
| `MC` | Monaco | Monaco=4568 |
| `OM` | Oman | Salalah=26007 |
| `PA` | Panama | Panama City=1218 |
| `PH` | Philippines | Manila=1243 |
| `PT` | Portugal | Lisbon=2929 |
| `PR` | Puerto Rico | San Juan=3439 |
| `AE` | United Arab Emirates | Dubai=3049 |
| `RS` | Serbia | Belgrade=26004 |

## Login and two-factor authentication

Gluetun logs in on its own the first time, and again whenever the stored
session stops working:

1. It reuses the stored access token if that token has not expired.
1. Otherwise, it uses the stored single sign-on session cookie
   (`fusionauth.sso`), which does not need the password.
1. Otherwise, it logs in with the username and password. If two-factor
   authentication is enabled, it generates the 6-digit code from
   `PUREVPN_TOTP_SECRET`, and asks PureVPN to trust the device
   (`trustComputer`), which may let later logins skip the code. If PureVPN
   rejects the code, Gluetun waits for the next 30-second code and submits
   it once before failing.

The TOTP secret is the text version of the QR code shown when you enable
two-factor authentication. It is often shown as "Can't scan the code?".
Only authenticator app two-factor authentication is supported. If PureVPN
shows the code form, Gluetun uses it directly. If it only shows a method
selection, Gluetun picks the authenticator app method; if there is none
(only email or SMS codes), the login fails.

### Session token

If you do not want to give Gluetun your password or TOTP secret, log in
once in a browser instead:

1. Log in to [my.purevpn.com](https://my.purevpn.com), and check "keep me
   signed in" if it is offered.
1. Open the browser developer tools, then Application (Chrome) or Storage
   (Firefox), then Cookies, then `https://auth.purevpn.com`.
1. Copy the value of the `fusionauth.sso` cookie into
   `PUREVPN_SESSION_TOKEN`.

Gluetun stores and refreshes the session itself. A new token replaces the
stored single sign-on session but keeps the other stored cookies, such as
the trusted device cookie. When the session finally expires, Gluetun falls
back to the username and password if they are set; otherwise it fails with
`PureVPN login session expired and PureVPN account username and password
are not set`, and you need to set a new token. You can also paste the
`fa_token` cookie of `my.purevpn.com`, but it expires after a short time.

## Kill switch

With the firewall enabled (the default), all traffic is blocked until the
VPN is up, including the PureVPN website. To fetch the configuration,
Gluetun briefly opens the firewall as follows:

1. It adds temporary rules allowing HTTPS (TCP 443) to the IPv4 addresses
   of the Cloudflare and Google DNS over HTTPS servers, through the default
   route interfaces.
1. It resolves `auth.purevpn.com` and `my.purevpn.com` with its own DNS
   over HTTPS client, which connects to these pinned IP addresses. The
   system DNS is not used. Responses are checked: they must match the
   query, and only A records of the queried name or its CNAME chain are
   used.
1. It adds temporary rules allowing HTTPS to the resolved PureVPN IPv4
   addresses only. Its HTTP client refuses any other destination and never
   uses a proxy.
1. It fetches the configuration, then removes all these rules before the
   WireGuard tunnel starts. The rules are also removed if the fetch fails,
   is interrupted or Gluetun shuts down. The whole fetch is limited to 2
   minutes.

The PureVPN website is behind Cloudflare, so its IP addresses are shared
with many other websites. To keep other programs from reaching those sites
outside the VPN while the rules exist, the rules only accept packets that
match both:

- a socket mark, set only on Gluetun's sockets for this fetch. The mark is
  random, changes on every fetch, and is shown as `<redacted>` in the logs.
- Gluetun's own cgroup (`-m cgroup --path <path>`, with the cgroup v2 path
  read from `/proc/self/cgroup`). Containers sharing Gluetun's network
  namespace (for example with `network_mode: service:gluetun`) run in other
  cgroups, so they cannot match. The mark alone is not enough: a process
  with the `NET_RAW` capability, granted by Docker by default, can set
  socket marks on Linux 5.17 and later, so it could try mark values until
  one works.

The cgroup match is best effort. If the cgroup v2 path is not found, or the
cgroup match is not supported, Gluetun logs a warning once and the rules
only match the mark. In all cases, a program with the `NET_ADMIN`
capability can read the rules and their mark.

If removing a rule fails, Gluetun logs a warning and tries again at the
start of the next fetch, logging `removed temporary firewall rules left by
a previous attempt` once it succeeds. With the firewall disabled, no rules
are added.

## Reconnection

PureVPN removes WireGuard peers that are not used, so Gluetun requests a
new configuration on every connection attempt. This includes reconnects
after a failed health check. If PureVPN rejects the access token, Gluetun
logs in again once and retries.

## Control server

`GET /v1/vpn/settings` shows `[redacted]` instead of the PureVPN password,
TOTP secret and session token when they are set. When updating settings
with `PUT /v1/vpn/settings`, a value of `[redacted]` keeps the stored
secret, so you can send back the settings you received.

## Errors

| Error | Meaning |
| --- | --- |
| `PureVPN rejected the account username or password` | Wrong credentials, shown with PureVPN's own message |
| `two-factor authentication is enabled on the PureVPN account but no TOTP secret is set` | Set `PUREVPN_TOTP_SECRET` or `PUREVPN_SESSION_TOKEN` |
| `PureVPN rejected the two-factor code, check the TOTP secret and the system clock` | Wrong TOTP secret, or the system clock is off |
| `PureVPN two-factor method is not supported, only authenticator app (TOTP) is supported` | The account only has email or SMS codes |
| `PureVPN requires a captcha to log in, log in once from a browser or set a session token` | Too many logins, see below |
| `PureVPN account username and password are not set` | The session token expired, or is not usable, and no username and password are set. After an expired session, it is prefixed with `PureVPN login session expired and` |
| `request blocked by the PureVPN website protection` | Cloudflare blocked the request, usually because of the IP address reputation |
| `no active PureVPN subscription found` | The account has no active subscription |
| `PureVPN subscription not found` | `PUREVPN_SUBSCRIPTION_ID` or `PUREVPN_VPN_USERNAME` matches no subscription; the error lists the ones available |
| `unexpected response from PureVPN` | PureVPN probably changed its website, so please report it. This includes an unexpected page after the two-factor step |

To avoid getting the account locked or captcha-protected by repeated
failed logins, Gluetun does not retry credential and two-factor errors (the
first, second, third, fourth and sixth rows) with the same settings. The
first failure ends with `- change the PureVPN settings to retry, through
the control server or by restarting with fixed settings`. Later connection
attempts fail immediately with `not retrying with unchanged PureVPN
settings: ...`, without contacting PureVPN, until any PureVPN setting
changes. The VPN loop keeps cycling, but no login happens.

A captcha may stop being required after a while, so it only pauses logins
for one hour. The error ends with `- not contacting PureVPN again before
<time>, unless the PureVPN settings change`, and attempts during that hour
fail with `not retrying with unchanged PureVPN settings: ...`. To avoid it,
log in once from a browser, or use a [session token](#session-token).

Other errors, such as network errors, Cloudflare blocks and unexpected
responses, are retried by the VPN loop with a delay that doubles after each
failure, starting at 15 seconds.

## Testing your settings without Docker

To check your account settings against the real PureVPN website without
starting a VPN, run from the repository root:

```sh
PUREVPN_LIVE_TEST="$PWD/purevpn-wireguard.env" \
  go test -count=1 -run Test_Live -v ./internal/provider/purevpn/wgapi/
```

`PUREVPN_LIVE_TEST` is the path to your env file. The test logs in,
requests a configuration with a throwaway key and prints it, without the
private key. It talks to PureVPN directly, without the firewall rules or
the stored session. Set `PUREVPN_LIVE_EXPECT=invalid_credentials` to check
that fake credentials are rejected as such.
