package wgapi

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/net/html"
)

func (c *Client) authorizeURL() *url.URL {
	authorizeURL := joinURL(c.authURL, "/oauth2/authorize")
	values := url.Values{}
	values.Set("client_id", clientID)
	values.Set("response_type", "code")
	values.Set("redirect_uri", joinURL(c.appURL, "/v2/api/fusionauth/login").String())
	authorizeURL.RawQuery = values.Encode()
	return authorizeURL
}

// loginWithSSO uses the single sign-on session cookie to get
// a new access token without the account credentials.
// It returns errSessionExpired if the session is no longer valid.
func (c *Client) loginWithSSO(ctx context.Context) (token string, err error) {
	page, err := c.doAuthRequest(ctx, http.MethodGet, c.authorizeURL().String(), nil)
	if err != nil {
		return "", err
	}

	token = c.getAccessTokenCookie()
	if token != "" {
		return token, nil
	}

	if page.findForm(isLoginForm) != nil || page.findForm(isTwoFactorForm) != nil {
		return "", errSessionExpired
	}
	return "", fmt.Errorf("%w: no access token after single sign-on redirect to %s",
		errUnexpectedResponse, page.url)
}

// loginWithCredentials logs in using the account username, password
// and, if needed, a two-factor code generated from the TOTP secret.
func (c *Client) loginWithCredentials(ctx context.Context) (token string, err error) {
	page, err := c.doAuthRequest(ctx, http.MethodGet, c.authorizeURL().String(), nil)
	if err != nil {
		return "", fmt.Errorf("loading login page: %w", err)
	}

	token = c.getAccessTokenCookie()
	if token != "" { // already logged in through a cookie
		return token, nil
	}

	loginForm := page.findForm(isLoginForm)
	if loginForm == nil {
		return "", fmt.Errorf("%w: login form not found at %s", errUnexpectedResponse, page.url)
	}

	values := loginForm.values()
	setDefault(values, "client_id", clientID)
	setDefault(values, "tenantId", tenantID)
	setDefault(values, "response_type", "code")
	setDefault(values, "redirect_uri", joinURL(c.appURL, "/v2/api/fusionauth/login").String())
	setDefault(values, "timezone", "UTC")
	values.Set("metaData.device.name", "Gluetun")
	values.Set("metaData.device.type", "BROWSER")
	values.Set("showPasswordField", "true")
	values.Set("loginId", c.credentials.Username)
	values.Set("password", c.credentials.Password)

	page, err = c.submitForm(ctx, page, loginForm, values)
	if err != nil {
		return "", fmt.Errorf("submitting login form: %w", err)
	}

	const maxSteps = 3 // two-factor method selection, then code, then maybe trust device
	for range maxSteps {
		token = c.getAccessTokenCookie()
		if token != "" {
			return token, nil
		}

		switch {
		case page.findForm(isTwoFactorMethodsForm) != nil:
			page, err = c.selectTwoFactorMethod(ctx, page)
		case page.findForm(isTwoFactorForm) != nil:
			page, err = c.submitTwoFactorCode(ctx, page)
		case page.findForm(isLoginForm) != nil:
			return "", loginPageError(page)
		default:
			return "", fmt.Errorf("%w: no access token after logging in, landed on %s",
				errUnexpectedResponse, page.url)
		}
		if err != nil {
			return "", err
		}
	}

	return "", fmt.Errorf("%w: too many login steps, landed on %s", errUnexpectedResponse, page.url)
}

func (c *Client) selectTwoFactorMethod(ctx context.Context, page *htmlPage) (*htmlPage, error) {
	form := page.findForm(isTwoFactorMethodsForm)
	values := form.values()
	methodID := ""
	for _, input := range form.inputs {
		if input.name != "methodId" {
			continue
		}
		if methodID == "" {
			methodID = input.value // first method as fallback
		}
		if strings.Contains(strings.ToLower(input.label+" "+input.id), "authenticator") {
			methodID = input.value
			break
		}
	}
	if methodID == "" {
		return nil, fmt.Errorf("%w: no two-factor method found", errUnexpectedResponse)
	}
	values.Set("methodId", methodID)
	page, err := c.submitForm(ctx, page, form, values)
	if err != nil {
		return nil, fmt.Errorf("selecting two-factor method: %w", err)
	}
	if page.findForm(isTwoFactorForm) == nil && c.getAccessTokenCookie() == "" {
		// The only method left is likely email or SMS.
		return nil, errTwoFactorMethodUnsupported
	}
	return page, nil
}

func (c *Client) submitTwoFactorCode(ctx context.Context, page *htmlPage) (*htmlPage, error) {
	if c.credentials.TOTPSecret == "" {
		return nil, errTwoFactorRequired
	}
	code, err := totpCode(c.credentials.TOTPSecret, c.timeNow())
	if err != nil {
		return nil, err
	}

	form := page.findForm(isTwoFactorForm)
	values := form.values()
	values.Set("code", code)
	// Ask FusionAuth to trust this device, so the fusionauth.trust
	// cookie, persisted in the session, can skip future 2FA prompts.
	values.Set("trustComputer", "true")
	page, err = c.submitForm(ctx, page, form, values)
	if err != nil {
		return nil, fmt.Errorf("submitting two-factor code: %w", err)
	}

	if c.getAccessTokenCookie() == "" && page.findForm(isTwoFactorForm) != nil {
		return nil, fmt.Errorf("%w: %s", errTwoFactorCodeInvalid, page.errorMessage())
	}
	return page, nil
}

func totpCode(secret string, now time.Time) (code string, err error) {
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	code, err = totp.GenerateCode(secret, now)
	if err != nil {
		return "", fmt.Errorf("generating two-factor code from TOTP secret: %w", err)
	}
	return code, nil
}

func loginPageError(page *htmlPage) error {
	// Note: the login form always has a hidden captcha_token input,
	// so only the error message tells if a captcha is required.
	message := page.errorMessage()
	switch {
	case strings.Contains(strings.ToLower(message), "captcha"):
		return fmt.Errorf("%w: %s", errCaptchaRequired, message)
	case message == "":
		return fmt.Errorf("%w: login page shown again without error message", errInvalidCredentials)
	default:
		return fmt.Errorf("%w: %s", errInvalidCredentials, message)
	}
}

func setDefault(values url.Values, key, value string) {
	if values.Get(key) == "" {
		values.Set(key, value)
	}
}

func (c *Client) submitForm(ctx context.Context, page *htmlPage,
	form *htmlForm, values url.Values,
) (*htmlPage, error) {
	action, err := page.url.Parse(form.action)
	if err != nil {
		return nil, fmt.Errorf("parsing form action: %w", err)
	}
	return c.doAuthRequest(ctx, http.MethodPost, action.String(), values)
}

// doAuthRequest does a request to the auth server, following redirects,
// and returns the final HTML page.
func (c *Client) doAuthRequest(ctx context.Context, method, rawURL string,
	form url.Values,
) (page *htmlPage, err error) {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	request, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	setBrowserHeaders(request)
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", c.authURL.Scheme+"://"+c.authURL.Host)
		request.Header.Set("Referer", rawURL)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, wrapRequestError(err)
	}
	defer response.Body.Close()

	responseBody, err := readBody(response)
	if err != nil {
		return nil, err
	}

	err = checkBlocked(response, responseBody)
	if err != nil {
		return nil, err
	}

	page = &htmlPage{url: response.Request.URL, body: responseBody}
	if c.getAccessTokenCookie() != "" {
		// Logged in, the final page content does not matter.
		return page, nil
	}

	if response.StatusCode >= http.StatusInternalServerError {
		return nil, fmt.Errorf("%w: %s %s returned %s",
			errUnexpectedResponse, method, response.Request.URL.Redacted(), response.Status)
	}

	page.forms, page.errors = parseHTML(responseBody)
	return page, nil
}

type htmlPage struct {
	url    *url.URL
	body   []byte
	forms  []*htmlForm
	errors []string
}

type htmlForm struct {
	action string
	inputs []htmlInput
}

type htmlInput struct {
	name    string
	value   string
	id      string
	typ     string
	checked bool
	label   string
}

func (p *htmlPage) findForm(match func(form *htmlForm) bool) *htmlForm {
	for _, form := range p.forms {
		if match(form) {
			return form
		}
	}
	return nil
}

func (p *htmlPage) errorMessage() string {
	return strings.Join(p.errors, "; ")
}

func (f *htmlForm) hasInput(name string) bool {
	for _, input := range f.inputs {
		if input.name == name {
			return true
		}
	}
	return false
}

// values returns the form values, excluding unchecked radio
// buttons and checkboxes, and submit buttons.
func (f *htmlForm) values() url.Values {
	values := url.Values{}
	for _, input := range f.inputs {
		switch {
		case input.name == "",
			input.typ == "submit", input.typ == "button",
			(input.typ == "radio" || input.typ == "checkbox") && !input.checked:
			continue
		}
		values.Set(input.name, input.value)
	}
	return values
}

func isLoginForm(form *htmlForm) bool {
	return form.hasInput("loginId") && form.hasInput("password")
}

func isTwoFactorForm(form *htmlForm) bool {
	return form.hasInput("code") && form.hasInput("twoFactorId")
}

func isTwoFactorMethodsForm(form *htmlForm) bool {
	return form.hasInput("methodId") && !form.hasInput("code")
}

// parseHTML extracts the forms and the error messages from an HTML page.
// FusionAuth themes show errors in elements with an "error" class or
// an "alert" role.
func parseHTML(body []byte) (forms []*htmlForm, errorMessages []string) {
	root, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, nil
	}

	parser := &htmlParser{labels: make(map[string]string)}
	parser.walk(root)

	for _, form := range parser.forms {
		for i := range form.inputs {
			form.inputs[i].label = parser.labels[form.inputs[i].id]
		}
	}
	return parser.forms, parser.errorMessages
}

type htmlParser struct {
	forms         []*htmlForm
	currentForm   *htmlForm
	labels        map[string]string // input id to label text
	errorMessages []string
}

func (p *htmlParser) walk(node *html.Node) {
	if node.Type == html.ElementNode {
		p.handleElement(node)
		if isErrorElement(node) {
			text := strings.Join(strings.Fields(textContent(node)), " ")
			if text != "" {
				p.errorMessages = append(p.errorMessages, text)
			}
			return // do not collect nested error elements twice
		}
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		p.walk(child)
	}
}

func (p *htmlParser) handleElement(node *html.Node) {
	switch node.Data {
	case "form":
		p.currentForm = &htmlForm{action: attribute(node, "action")}
		p.forms = append(p.forms, p.currentForm)
	case "input", "button", "textarea", "select":
		if p.currentForm == nil {
			return
		}
		_, checked := attributeExists(node, "checked")
		p.currentForm.inputs = append(p.currentForm.inputs, htmlInput{
			name:    attribute(node, "name"),
			value:   attribute(node, "value"),
			id:      attribute(node, "id"),
			typ:     strings.ToLower(attribute(node, "type")),
			checked: checked,
		})
	case "label":
		forID := attribute(node, "for")
		if forID != "" {
			p.labels[forID] = strings.TrimSpace(textContent(node))
		}
	}
}

func isErrorElement(node *html.Node) bool {
	if attribute(node, "role") == "alert" {
		return true
	}
	for class := range strings.FieldsSeq(attribute(node, "class")) {
		switch class {
		case "error", "errors", "alert-error", "alert-danger":
			return true
		}
	}
	return false
}

func attribute(node *html.Node, key string) string {
	value, _ := attributeExists(node, key)
	return value
}

func attributeExists(node *html.Node, key string) (value string, ok bool) {
	for _, attr := range node.Attr {
		if attr.Key == key {
			return attr.Val, true
		}
	}
	return "", false
}

func textContent(node *html.Node) string {
	var builder strings.Builder
	var walk func(node *html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			builder.WriteString(node.Data)
			builder.WriteString(" ")
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return builder.String()
}
