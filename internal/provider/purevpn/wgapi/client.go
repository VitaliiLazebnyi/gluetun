package wgapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// DefaultAuthURL is the PureVPN FusionAuth server base URL.
const DefaultAuthURL = "https://auth.purevpn.com"

// DefaultAppURL is the PureVPN member area base URL.
const DefaultAppURL = "https://my.purevpn.com"

// clientID is the FusionAuth client identifier of the
// PureVPN member area application.
const clientID = "ed1ee674-0a34-4265-b4a1-141b721036eb"

// accessToken is the name of the member area access token cookie.
const accessToken = "fa_token"

// Credentials are the PureVPN account credentials.
type Credentials struct {
	// Username is the PureVPN account email address.
	Username string
	// Password is the PureVPN account password.
	Password string
	// TOTPSecret is the base32 secret of the authenticator app
	// two-factor authentication, and can be left empty if
	// two-factor authentication is disabled.
	TOTPSecret string
}

// Session is the login state which can be persisted to avoid
// logging in with the account credentials on every restart.
type Session struct {
	// AccessToken is the short lived JWT access token
	// (fa_token cookie) used for the member area API.
	AccessToken string `json:"access_token,omitempty"`
	// AuthCookies are the auth.purevpn.com cookies, notably the
	// long lived fusionauth.sso single sign-on session cookie
	// and the fusionauth.trust two-factor trusted device cookie.
	AuthCookies map[string]string `json:"auth_cookies,omitempty"`
}

// WithSessionToken returns a copy of the session using the session
// token given. A JWT token is used as the access token, and any other
// token is used as the fusionauth.sso single sign-on cookie, in which
// case the access token from the previous single sign-on session is
// cleared. Other authentication cookies are kept.
func (s Session) WithSessionToken(token string) Session {
	updated := Session{AccessToken: s.AccessToken, AuthCookies: maps.Clone(s.AuthCookies)}
	if IsJWT(token) {
		updated.AccessToken = token
		return updated
	}
	if updated.AuthCookies == nil {
		updated.AuthCookies = make(map[string]string, 1)
	}
	updated.AuthCookies["fusionauth.sso"] = token
	updated.AccessToken = ""
	return updated
}

// Client is a PureVPN member area API client.
// It is not safe for concurrent use.
type Client struct {
	// httpClient is a copy of the HTTP client given to [New],
	// with its cookie jar replaced on each login.
	httpClient  *http.Client
	authURL     *url.URL
	appURL      *url.URL
	credentials Credentials
	timeNow     func() time.Time

	session Session
}

// New creates a new client using a copy of the HTTP client given,
// which refuses redirects to hosts other than the auth and app hosts.
// authURL and appURL can be left empty to use the defaults.
func New(httpClient *http.Client, authURL, appURL string,
	credentials Credentials, session Session,
) (client *Client, err error) {
	if authURL == "" {
		authURL = DefaultAuthURL
	}
	if appURL == "" {
		appURL = DefaultAppURL
	}
	client = &Client{
		credentials: credentials,
		timeNow:     time.Now,
	}
	client.authURL, err = url.Parse(authURL)
	if err != nil {
		return nil, fmt.Errorf("parsing auth URL: %w", err)
	}
	client.appURL, err = url.Parse(appURL)
	if err != nil {
		return nil, fmt.Errorf("parsing app URL: %w", err)
	}

	httpClientCopy := *httpClient
	httpClientCopy.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		err := client.checkHost(request.URL)
		switch {
		case err != nil:
			return fmt.Errorf("redirect: %w", err)
		case httpClient.CheckRedirect != nil:
			return httpClient.CheckRedirect(request, via)
		}
		const maxRedirects = 10
		if len(via) >= maxRedirects {
			return fmt.Errorf("%w: stopped after %d redirects", errUnexpectedResponse, maxRedirects)
		}
		return nil
	}
	// The cookie jar is replaced on each login.
	httpClientCopy.Jar = newCookieJar(client.authURL, nil)
	client.httpClient = &httpClientCopy
	client.session = Session{AccessToken: session.AccessToken, AuthCookies: maps.Clone(session.AuthCookies)}

	return client, nil
}

// checkHost returns an error if the URL given is not on the scheme
// and host of the auth URL or of the app URL, so the credentials and
// the access token are never sent elsewhere.
func (c *Client) checkHost(target *url.URL) error {
	for _, allowed := range [...]*url.URL{c.authURL, c.appURL} {
		if target.Scheme == allowed.Scheme && target.Host == allowed.Host {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", errHostNotAllowed, target.Host)
}

// Session returns a copy of the current session.
func (c *Client) Session() Session {
	return Session{AccessToken: c.session.AccessToken, AuthCookies: maps.Clone(c.session.AuthCookies)}
}

// newCookieJar returns a cookie jar holding the auth cookies given,
// set as host-only cookies with the path "/" for the auth URL,
// which is how the auth server sets them.
func newCookieJar(authURL *url.URL, authCookies map[string]string) *cookiejar.Jar {
	jar, _ := cookiejar.New(nil) // never returns an error
	cookies := make([]*http.Cookie, 0, len(authCookies))
	for name, value := range authCookies {
		cookies = append(cookies, &http.Cookie{Name: name, Value: value, Path: "/"})
	}
	jar.SetCookies(authURL, cookies)
	return jar
}

// saveSession records the current access token and auth cookies
// from the cookie jar into the session.
func (c *Client) saveSession(token string) {
	c.session.AccessToken = token
	authCookies := make(map[string]string)
	// Cookies are sorted with the most specific path first.
	for _, cookie := range c.httpClient.Jar.Cookies(joinURL(c.authURL, "/oauth2/authorize")) {
		_, alreadySet := authCookies[cookie.Name]
		if !strings.HasPrefix(cookie.Name, "fusionauth.") || alreadySet {
			continue
		}
		authCookies[cookie.Name] = cookie.Value
	}
	c.session.AuthCookies = authCookies
}

// accessTokenValid returns true if the access token is set,
// is a JWT and does not expire within the next minute.
// If the token is not a JWT, it is assumed to be valid.
func accessTokenValid(token string, now time.Time) bool {
	if token == "" {
		return false
	}
	expiry, ok := jwtExpiry(token)
	if !ok {
		return true
	}
	const margin = time.Minute
	return now.Add(margin).Before(expiry)
}

func jwtExpiry(token string) (expiry time.Time, ok bool) {
	parts := strings.Split(token, ".")
	const jwtParts = 3
	if len(parts) != jwtParts {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	err = json.Unmarshal(payload, &claims)
	if err != nil || claims.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}

// IsJWT returns true if the token looks like a JWT.
func IsJWT(token string) bool {
	_, ok := jwtExpiry(token)
	return ok
}

func setBrowserHeaders(request *http.Request) {
	// The website is behind Cloudflare, which is more likely to block
	// requests not looking like they come from a browser.
	const userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if request.Header.Get("Accept") == "" {
		request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	}
}

func readBody(response *http.Response) (body []byte, err error) {
	const maxBodySize = 4 << 20
	body, err = io.ReadAll(io.LimitReader(response.Body, maxBodySize))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	return body, nil
}

// checkBlocked returns errBlocked if the response looks like a
// Cloudflare block or challenge page.
func checkBlocked(response *http.Response, body []byte) error {
	if response.Header.Get("Cf-Mitigated") == "challenge" {
		return fmt.Errorf("%w: Cloudflare challenge for %s", errBlocked, response.Request.URL.Hostname())
	}
	switch response.StatusCode {
	case http.StatusForbidden, http.StatusServiceUnavailable, http.StatusTooManyRequests:
	default:
		return nil
	}
	if !strings.Contains(response.Header.Get("Server"), "cloudflare") {
		return nil
	}
	lowerBody := strings.ToLower(string(body))
	for _, marker := range [...]string{"cf-chl", "just a moment", "attention required", "cf-error-details"} {
		if strings.Contains(lowerBody, marker) {
			return fmt.Errorf("%w: Cloudflare returned %s for %s",
				errBlocked, response.Status, response.Request.URL.Hostname())
		}
	}
	return nil
}

// wrapRequestError redacts the URL query string, which can contain
// OAuth parameters, from the request error given.
func wrapRequestError(err error) error {
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		return err
	}
	parsedURL, parseErr := url.Parse(urlErr.URL)
	if parseErr == nil {
		urlErr.URL = redactURL(parsedURL)
	} else {
		urlErr.URL = "<redacted>"
	}
	if urlErr.Timeout() {
		return fmt.Errorf("timed out reaching PureVPN: %w", err)
	}
	return err
}

// redactURL returns the URL without its user information,
// query string and fragment.
func redactURL(fullURL *url.URL) string {
	redacted := url.URL{Scheme: fullURL.Scheme, Host: fullURL.Host, Path: fullURL.Path}
	return redacted.String()
}

// getAccessTokenCookie returns the access token cookie value
// from the cookie jar of the current login.
func (c *Client) getAccessTokenCookie() string {
	for _, cookie := range c.httpClient.Jar.Cookies(c.appURL) {
		if cookie.Name == accessToken && cookie.Value != "" {
			return cookie.Value
		}
	}
	return ""
}

// ensureAccessToken returns a valid access token, logging in if needed.
func (c *Client) ensureAccessToken(ctx context.Context) (token string, err error) {
	if accessTokenValid(c.session.AccessToken, c.timeNow()) {
		return c.session.AccessToken, nil
	}
	return c.login(ctx)
}

// login obtains a new access token, using the stored single sign-on
// session if it is still valid, and the account credentials otherwise.
// It uses a new cookie jar holding only the stored auth cookies, so an
// access token cookie from a previous login cannot be mistaken for the
// result of this login.
func (c *Client) login(ctx context.Context) (token string, err error) {
	c.session.AccessToken = ""
	if !c.credentialsSet() && len(c.session.AuthCookies) == 0 {
		return "", errCredentialsNotSet
	}
	c.httpClient.Jar = newCookieJar(c.authURL, c.session.AuthCookies)

	token, err = c.authenticate(ctx)
	if err != nil {
		return "", err
	}
	c.saveSession(token)
	return token, nil
}

func (c *Client) credentialsSet() bool {
	return c.credentials.Username != "" && c.credentials.Password != ""
}

// joinURL joins the absolute path given to the base URL, making
// sure the resulting path starts with a slash, which is not the case
// with [url.URL.JoinPath] when the base URL path is empty.
func joinURL(base *url.URL, absolutePath string) *url.URL {
	joined := base.JoinPath(absolutePath)
	if !strings.HasPrefix(joined.Path, "/") {
		joined.Path = "/" + joined.Path
	}
	return joined
}
