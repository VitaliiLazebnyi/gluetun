package wgapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultAuthURL is the PureVPN FusionAuth server base URL.
const DefaultAuthURL = "https://auth.purevpn.com"

// DefaultAppURL is the PureVPN member area base URL.
const DefaultAppURL = "https://my.purevpn.com"

// clientID and tenantID are the FusionAuth identifiers of the
// PureVPN member area application.
const clientID = "ed1ee674-0a34-4265-b4a1-141b721036eb"

const tenantID = "9707f41e-21a4-bbc5-dcbc-fdf6b61cc68f"

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

// Client is a PureVPN member area API client.
// It is safe for concurrent use.
type Client struct {
	httpClient  *http.Client
	authURL     *url.URL
	appURL      *url.URL
	credentials Credentials
	timeNow     func() time.Time

	mutex   sync.Mutex
	session Session
}

// New creates a new client using the HTTP client given, which should
// not follow redirects differently than the default policy.
// A cookie jar is set on a copy of the HTTP client given.
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

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("creating cookie jar: %w", err)
	}
	httpClientCopy := *httpClient
	httpClientCopy.Jar = jar
	client.httpClient = &httpClientCopy
	client.setSession(session)

	return client, nil
}

// Session returns a copy of the current session.
func (c *Client) Session() Session {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.copySession()
}

func (c *Client) copySession() Session {
	cookies := make(map[string]string, len(c.session.AuthCookies))
	for name, value := range c.session.AuthCookies {
		cookies[name] = value
	}
	return Session{AccessToken: c.session.AccessToken, AuthCookies: cookies}
}

func (c *Client) setSession(session Session) {
	c.session = session
	cookies := make([]*http.Cookie, 0, len(session.AuthCookies))
	for name, value := range session.AuthCookies {
		cookies = append(cookies, &http.Cookie{Name: name, Value: value, Path: "/"})
	}
	c.httpClient.Jar.SetCookies(c.authURL, cookies)
}

// saveSession records the current access token and auth cookies
// from the cookie jar into the session.
func (c *Client) saveSession(token string) {
	c.session.AccessToken = token
	authCookies := make(map[string]string)
	for _, cookie := range c.httpClient.Jar.Cookies(joinURL(c.authURL, "/oauth2/authorize")) {
		if strings.HasPrefix(cookie.Name, "fusionauth.") {
			authCookies[cookie.Name] = cookie.Value
		}
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
		return fmt.Errorf("%w: Cloudflare challenge for %s", errBlocked, response.Request.URL.Host)
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
	for _, marker := range []string{"cf-chl", "just a moment", "attention required", "cf-error-details"} {
		if strings.Contains(lowerBody, marker) {
			return fmt.Errorf("%w: Cloudflare returned %s for %s",
				errBlocked, response.Status, response.Request.URL.Host)
		}
	}
	return nil
}

func wrapRequestError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Timeout() {
		return fmt.Errorf("timed out reaching PureVPN: %w", err)
	}
	return err
}

func (c *Client) getAccessTokenCookie() string {
	for _, cookie := range c.httpClient.Jar.Cookies(c.appURL) {
		if cookie.Name == accessToken && cookie.Value != "" {
			return cookie.Value
		}
	}
	return ""
}

// ensureAccessToken returns a valid access token, logging in if needed.
// The caller must hold the client mutex.
func (c *Client) ensureAccessToken(ctx context.Context) (token string, err error) {
	if accessTokenValid(c.session.AccessToken, c.timeNow()) {
		return c.session.AccessToken, nil
	}
	return c.login(ctx)
}

// login obtains a new access token, first using the stored single sign-on
// session if any, and then falling back on the account credentials.
// The caller must hold the client mutex.
func (c *Client) login(ctx context.Context) (token string, err error) {
	c.session.AccessToken = ""
	if len(c.session.AuthCookies) > 0 {
		token, err = c.loginWithSSO(ctx)
		switch {
		case err == nil:
			c.saveSession(token)
			return token, nil
		case !errors.Is(err, errSessionExpired):
			return "", fmt.Errorf("logging in with stored session: %w", err)
		}
		// Session expired, fall back on the credentials.
	}

	if c.credentials.Username == "" || c.credentials.Password == "" {
		if len(c.session.AuthCookies) > 0 {
			return "", fmt.Errorf("%w and %w", errSessionExpired, errCredentialsNotSet)
		}
		return "", errCredentialsNotSet
	}

	token, err = c.loginWithCredentials(ctx)
	if err != nil {
		return "", err
	}
	c.saveSession(token)
	return token, nil
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
