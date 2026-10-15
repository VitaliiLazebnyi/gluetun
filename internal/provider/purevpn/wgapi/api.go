package wgapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ServerRequest contains the parameters to request a WireGuard server.
type ServerRequest struct {
	// CountryCode is the ISO 3166 alpha-2 country code, for example "US".
	CountryCode string
	// CityID is the optional PureVPN city ID, for example 8778 for New York.
	CityID uint
	// SubscriptionID is the optional subscription ID to use,
	// if the account has more than one subscription.
	SubscriptionID string
	// VPNUsername is the optional VPN username (purevpn0sXXXXX)
	// to use, if the subscription has more than one.
	VPNUsername string
	// ClientPublicKey is the WireGuard public key of the client,
	// whose private key never leaves the client.
	ClientPublicKey string
}

// FetchConfig logs in if needed and requests a WireGuard configuration.
// If the API rejects the access token, it logs in again once and retries.
func (c *Client) FetchConfig(ctx context.Context, request ServerRequest) (
	config Config, err error,
) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	config, err = c.fetchConfig(ctx, request)
	if !errors.Is(err, errUnauthorized) {
		return config, err
	}

	// The access token was likely revoked or expired early.
	_, err = c.login(ctx)
	if err != nil {
		return Config{}, fmt.Errorf("logging in again after access token was rejected: %w", err)
	}
	return c.fetchConfig(ctx, request)
}

func (c *Client) fetchConfig(ctx context.Context, request ServerRequest) (
	config Config, err error,
) {
	token, err := c.ensureAccessToken(ctx)
	if err != nil {
		return Config{}, err
	}

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
		return Config{}, fmt.Errorf("getting WireGuard server: %w", err)
	}
	return config, nil
}

type apiResponse struct {
	Status  bool            `json:"status"`
	Message string          `json:"message"`
	Body    json.RawMessage `json:"body"`
}

func (c *Client) apiRequest(ctx context.Context, token, path string,
	form url.Values, body any,
) (err error) {
	if form == nil {
		form = url.Values{}
	}
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

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: %s returned %s", errUnauthorized, path, response.Status)
	default:
		return fmt.Errorf("%w: %s returned %s: %s", errAPI, path, response.Status,
			truncate(string(responseBody)))
	}

	var data apiResponse
	err = json.Unmarshal(responseBody, &data)
	if err != nil {
		if strings.HasPrefix(strings.TrimSpace(string(responseBody)), "<") {
			// HTML page instead of JSON, usually the login page
			// after a redirect because the token is not accepted.
			return fmt.Errorf("%w: %s returned an HTML page", errUnauthorized, path)
		}
		return fmt.Errorf("%w: decoding %s response: %w", errUnexpectedResponse, path, err)
	}

	if !data.Status {
		if isAuthMessage(data.Message) {
			return fmt.Errorf("%w: %s: %s", errUnauthorized, path, data.Message)
		}
		return fmt.Errorf("%w: %s: %s", errAPI, path, data.Message)
	}

	if body == nil {
		return nil
	}
	err = json.Unmarshal(data.Body, body)
	if err != nil {
		return fmt.Errorf("%w: decoding %s response body: %w", errUnexpectedResponse, path, err)
	}
	return nil
}

func isAuthMessage(message string) bool {
	message = strings.ToLower(message)
	for _, keyword := range []string{"unauthori", "token", "expired", "session", "login"} {
		if strings.Contains(message, keyword) {
			return true
		}
	}
	return false
}

func truncate(s string) string {
	const maxLength = 200
	s = strings.TrimSpace(s)
	if len(s) <= maxLength {
		return s
	}
	return s[:maxLength] + "..."
}

type subscription struct {
	ID           string   `json:"id"`
	State        string   `json:"state"`
	Status       string   `json:"status"`
	VPNUsernames []string `json:"vpnusernames"`
}

func (s subscription) active() bool {
	state := s.State
	if state == "" {
		state = s.Status
	}
	return state == "" || strings.EqualFold(state, "active")
}

func (c *Client) selectSubscription(ctx context.Context, token,
	wantedID, wantedUsername string,
) (subscriptionID, vpnUsername string, err error) {
	subscriptions, err := c.getSubscriptions(ctx, token)
	if err != nil {
		return "", "", err
	}

	for _, sub := range subscriptions {
		switch {
		case wantedID != "" && sub.ID != wantedID,
			wantedID == "" && !sub.active(),
			len(sub.VPNUsernames) == 0:
			continue
		case wantedUsername == "":
			return sub.ID, sub.VPNUsernames[0], nil
		}
		for _, username := range sub.VPNUsernames {
			if username == wantedUsername {
				return sub.ID, username, nil
			}
		}
	}

	if wantedID != "" || wantedUsername != "" {
		return "", "", fmt.Errorf("%w: subscription ID %q and VPN username %q, available: %s",
			errSubscriptionNotFound, wantedID, wantedUsername, describeSubscriptions(subscriptions))
	}
	return "", "", errNoActiveSubscription
}

// getSubscriptions gets the account subscriptions, trying the
// subscription endpoint first and then the on-boarding endpoint,
// since both have been used by the member area.
func (c *Client) getSubscriptions(ctx context.Context, token string) (
	subscriptions []subscription, err error,
) {
	err = c.apiRequest(ctx, token, "/v2/api/subscription", nil, &subscriptions)
	if err == nil {
		return subscriptions, nil
	} else if !errors.Is(err, errAPI) && !errors.Is(err, errUnexpectedResponse) {
		return nil, err
	}
	subscriptionErr := err

	var onBoarding struct {
		Subscriptions []subscription `json:"subscriptions"`
	}
	err = c.apiRequest(ctx, token, "/v2/api/on-boarding", nil, &onBoarding)
	if err != nil {
		return nil, fmt.Errorf("%w; %w", subscriptionErr, err)
	}
	return onBoarding.Subscriptions, nil
}

func describeSubscriptions(subscriptions []subscription) string {
	descriptions := make([]string, len(subscriptions))
	for i, sub := range subscriptions {
		descriptions[i] = fmt.Sprintf("%s (%s) with VPN usernames %s",
			sub.ID, sub.State, strings.Join(sub.VPNUsernames, ", "))
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
	form.Set("sCountrySlug", strings.ToUpper(request.CountryCode))
	form.Set("sDeviceType", "linux")
	form.Set("sClientPublicKey", request.ClientPublicKey)
	form.Set("sSubsId", subscriptionID)
	// natServer=0 is only for port forwarding addon servers.
	form.Set("natServer", "1")
	if request.CityID != 0 {
		form.Set("iCityId", strconv.FormatUint(uint64(request.CityID), 10))
	}

	var raw json.RawMessage
	err = c.apiRequest(ctx, token, "/v2/api/wireguard/get-wg-server", form, &raw)
	if err != nil {
		return Config{}, err
	}

	// The body is a list of servers, but can also be a single object.
	var servers []wireguardServer
	err = json.Unmarshal(raw, &servers)
	if err != nil {
		var server wireguardServer
		err = json.Unmarshal(raw, &server)
		if err != nil {
			return Config{}, fmt.Errorf("%w: decoding server: %w", errUnexpectedResponse, err)
		}
		servers = []wireguardServer{server}
	}
	if len(servers) == 0 || servers[0].Configuration == "" {
		return Config{}, fmt.Errorf("%w: no WireGuard configuration in response", errUnexpectedResponse)
	}

	config, err = parseConfig(servers[0].Configuration)
	if err != nil {
		return Config{}, fmt.Errorf("%w: parsing WireGuard configuration: %w", errUnexpectedResponse, err)
	}
	config.ProtocolIP = servers[0].ProtocolIP
	return config, nil
}
