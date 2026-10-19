package wgapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// ServerRequest contains the parameters to request a Wireguard server.
type ServerRequest struct {
	// CountryCode is the uppercase ISO 3166 alpha-2 country code, for example "US".
	CountryCode string
	// CityID is the optional PureVPN city ID, for example 8778 for New York.
	CityID uint32
	// SubscriptionID is the optional subscription ID to use,
	// if the account has more than one subscription.
	SubscriptionID string
	// VPNUsername is the optional VPN username (purevpn0sXXXXX)
	// to use, if the subscription has more than one.
	VPNUsername string
	// ClientPublicKey is the Wireguard public key of the client,
	// whose private key never leaves the client.
	ClientPublicKey string
}

// FetchConfig logs in if needed and requests a Wireguard configuration.
// If the API rejects the stored access token, it logs in again once and
// retries. An access token obtained by logging in during this call is not
// retried, since logging in again would only double the login attempts.
func (c *Client) FetchConfig(ctx context.Context, request ServerRequest) (
	config Config, err error,
) {
	token, loggedIn, err := c.ensureAccessToken(ctx)
	if err != nil {
		return Config{}, err
	}

	config, err = c.fetchConfig(ctx, token, request)
	if !errors.Is(err, errUnauthorized) || loggedIn {
		return config, err
	}

	// The stored access token was likely revoked or expired early.
	token, err = c.login(ctx)
	if err != nil {
		return Config{}, fmt.Errorf("logging in again after access token was rejected: %w", err)
	}
	return c.fetchConfig(ctx, token, request)
}

func (c *Client) fetchConfig(ctx context.Context, token string, request ServerRequest) (
	config Config, err error,
) {
	subscriptionID, vpnUsername, err := c.selectSubscription(ctx, token,
		request.SubscriptionID, request.VPNUsername)
	if err != nil {
		return Config{}, fmt.Errorf("selecting subscription: %w", err)
	}

	encryptedPassword, err := c.getEncryptedPassword(ctx, token, vpnUsername)
	if err != nil {
		return Config{}, fmt.Errorf("getting VPN password: %w", err)
	}

	config, err = c.getWireguardServer(ctx, token, request, subscriptionID,
		vpnUsername, encryptedPassword)
	if err != nil {
		return Config{}, fmt.Errorf("getting Wireguard server: %w", err)
	}
	return config, nil
}

type apiResponse struct {
	Status    bool            `json:"status"`
	Message   string          `json:"message"`
	ErrorCode string          `json:"error_code"`
	Body      json.RawMessage `json:"body"`
}

func (c *Client) apiRequest(ctx context.Context, token, path string,
	form url.Values, body any,
) (err error) {
	requestURL := joinURL(c.appURL, path)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		requestURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	setBrowserHeaders(request)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	origin := c.appURL.Scheme + "://" + c.appURL.Host
	request.Header.Set("Origin", origin)
	request.Header.Set("Referer", origin+"/v2/dashboard/manual-config")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return wrapRequestError(err)
	}
	defer response.Body.Close()

	responseBody, err := readBody(response)
	if err != nil {
		return err
	}

	err = checkBlocked(response, responseBody)
	if err != nil {
		return err
	}

	isHTML := isHTMLResponse(response, responseBody)
	switch {
	case response.StatusCode == http.StatusOK:
	case response.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("%w: API returned %s", errUnauthorized, response.Status)
	case response.StatusCode == http.StatusForbidden && isHTML:
		// HTML error page from the website protection, not the API.
		return fmt.Errorf("%w: API returned %s with an HTML page", errBlocked, response.Status)
	default:
		return fmt.Errorf("%w: API returned %s: %s", errAPI, response.Status,
			truncate(string(responseBody)))
	}

	var data apiResponse
	err = json.Unmarshal(responseBody, &data)
	switch {
	case err != nil && isHTML:
		// HTML page instead of JSON, usually the login page
		// after a redirect because the token is not accepted.
		return fmt.Errorf("%w: API returned an HTML page", errUnauthorized)
	case err != nil:
		return fmt.Errorf("%w: decoding response: %w", errUnexpectedResponse, err)
	case !data.Status && data.ErrorCode == "token_expired":
		// The API answers with this error code and a 200 status
		// for any token it does not accept, expired or not.
		return fmt.Errorf("%w: %s", errUnauthorized, data.Message)
	case !data.Status:
		return fmt.Errorf("%w: %s", errAPI, data.Message)
	case body == nil:
		return nil
	}

	err = json.Unmarshal(data.Body, body)
	if err != nil {
		return fmt.Errorf("%w: decoding response body: %w", errUnexpectedResponse, err)
	}
	return nil
}

func isHTMLResponse(response *http.Response, body []byte) bool {
	return strings.Contains(response.Header.Get("Content-Type"), "text/html") ||
		bytes.HasPrefix(bytes.TrimSpace(body), []byte("<"))
}

// truncate trims and truncates the text given to
// at most 200 runes, followed by "..." if truncated.
func truncate(text string) string {
	const maxRunes = 200
	text = strings.TrimSpace(text)
	runeCount := 0
	for index := range text {
		if runeCount == maxRunes {
			return text[:index] + "..."
		}
		runeCount++
	}
	return text
}

type subscription struct {
	ID           string   `json:"id"`
	State        string   `json:"state"`
	VPNUsernames []string `json:"vpnusernames"`
}

func (c *Client) selectSubscription(ctx context.Context, token,
	wantedID, wantedUsername string,
) (subscriptionID, vpnUsername string, err error) {
	var subscriptions []subscription
	err = c.apiRequest(ctx, token, "/v2/api/subscription", nil, &subscriptions)
	if err != nil {
		return "", "", fmt.Errorf("requesting subscriptions: %w", err)
	}

	for _, candidate := range subscriptions {
		switch {
		case wantedID != "" && candidate.ID != wantedID,
			wantedID == "" && !strings.EqualFold(candidate.State, "active"),
			len(candidate.VPNUsernames) == 0:
			continue
		case wantedUsername == "":
			return candidate.ID, candidate.VPNUsernames[0], nil
		}
		if slices.Contains(candidate.VPNUsernames, wantedUsername) {
			return candidate.ID, wantedUsername, nil
		}
	}

	if wantedID != "" || wantedUsername != "" {
		return "", "", fmt.Errorf("%w: available subscriptions are %s",
			errSubscriptionNotFound, describeSubscriptions(subscriptions))
	}
	return "", "", errNoActiveSubscription
}

func describeSubscriptions(subscriptions []subscription) string {
	descriptions := make([]string, len(subscriptions))
	for i, accountSubscription := range subscriptions {
		descriptions[i] = fmt.Sprintf("%s (%s) with %d VPN username(s)", accountSubscription.ID,
			accountSubscription.State, len(accountSubscription.VPNUsernames))
	}
	if len(descriptions) == 0 {
		return "none"
	}
	return strings.Join(descriptions, "; ")
}

func (c *Client) getEncryptedPassword(ctx context.Context, token, vpnUsername string) (
	encryptedPassword string, err error,
) {
	form := url.Values{}
	form.Set("username", vpnUsername)
	var body struct {
		EncryptedPassword string `json:"encrypPass"`
	}
	err = c.apiRequest(ctx, token, "/v2/api/wireguard/get-encrypt-password", form, &body)
	if err != nil {
		return "", err
	}
	if body.EncryptedPassword == "" {
		return "", fmt.Errorf("%w: encrypted password is empty", errUnexpectedResponse)
	}
	return body.EncryptedPassword, nil
}

type wireguardServer struct {
	Configuration string `json:"wireguard_configuration"`
	ProtocolIP    string `json:"protocol_ip"`
}

func (c *Client) getWireguardServer(ctx context.Context, token string,
	request ServerRequest, subscriptionID, vpnUsername, encryptedPassword string,
) (config Config, err error) {
	form := url.Values{}
	form.Set("sUsername", vpnUsername)
	form.Set("sPassword", encryptedPassword)
	form.Set("sCountrySlug", request.CountryCode)
	form.Set("sDeviceType", "linux")
	form.Set("sClientPublicKey", request.ClientPublicKey)
	form.Set("sSubsId", subscriptionID)
	// natServer=0 is only for port forwarding addon servers.
	form.Set("natServer", "1")
	if request.CityID != 0 {
		form.Set("iCityId", strconv.FormatUint(uint64(request.CityID), 10))
	}

	var servers []wireguardServer
	err = c.apiRequest(ctx, token, "/v2/api/wireguard/get-wg-server", form, &servers)
	if err != nil {
		return Config{}, err
	}
	if len(servers) == 0 || servers[0].Configuration == "" {
		return Config{}, fmt.Errorf("%w: no Wireguard configuration in response", errUnexpectedResponse)
	}

	config, err = parseConfig(servers[0].Configuration)
	if err != nil {
		return Config{}, fmt.Errorf("%w: parsing Wireguard configuration: %w", errUnexpectedResponse, err)
	}
	if servers[0].ProtocolIP != "" {
		protocolIP, err := netip.ParseAddr(servers[0].ProtocolIP)
		if err != nil {
			return Config{}, fmt.Errorf("%w: parsing protocol IP: %w", errUnexpectedResponse, err)
		}
		config.ProtocolIP = protocolIP.Unmap()
	}
	return config, nil
}
