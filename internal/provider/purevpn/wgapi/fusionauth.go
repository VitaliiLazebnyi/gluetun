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

// authenticate gets a new access token, through the single sign-on
// session cookie if it is still valid, or else by logging in with the
// account username, password and, if needed, a two-factor code
// generated from the TOTP secret.
func (c *Client) authenticate(ctx context.Context) (token string, err error) {
	page, err := c.doAuthRequest(ctx, http.MethodGet, c.authorizeURL().String(), nil)
	if err != nil {
		return "", fmt.Errorf("loading login page: %w", err)
	}

	token = c.getAccessTokenCookie()
	if token != "" { // logged in through the single sign-on session
		return token, nil
	}

	// passwordSubmitted is true if the current page is the
	// response to the login form submission.
	passwordSubmitted := false
	loginForm := page.findForm(isLoginForm)
	switch {
	case page.findForm(isTwoFactorForm) != nil:
		// The single sign-on session is still valid but the two-factor
		// trusted device cookie expired, so go straight to two-factor.
	case loginForm == nil:
		return "", fmt.Errorf("%w: login form not found at %s with status %s",
			errUnexpectedResponse, redactURL(page.url), page.status)
	case !c.credentialsSet():
		// The login form is only shown without a valid single sign-on session.
		return "", fmt.Errorf("%w and %w", errSessionExpired, errCredentialsNotSet)
	default:
		page, err = c.submitLoginForm(ctx, page, loginForm)
		if err != nil {
			return "", fmt.Errorf("submitting login form: %w", err)
		}
		passwordSubmitted = true
	}

	if page.findForm(isTwoFactorForm) != nil {
		page, err = c.submitTwoFactorCode(ctx, page)
		if err != nil {
			return "", err
		}
		passwordSubmitted = false
	}

	token = c.getAccessTokenCookie()
	switch {
	case token != "":
		return token, nil
	case passwordSubmitted && page.findForm(isLoginForm) != nil:
		return "", loginPageError(page)
	default:
		return "", fmt.Errorf("%w: no access token after logging in, landed on %s with status %s",
			errUnexpectedResponse, redactURL(page.url), page.status)
	}
}

func (c *Client) submitLoginForm(ctx context.Context, page *htmlPage,
	loginForm *htmlForm,
) (*htmlPage, error) {
	values := loginForm.values()
	setDefault(values, "client_id", clientID)
	const tenantID = "9707f41e-21a4-bbc5-dcbc-fdf6b61cc68f"
	setDefault(values, "tenantId", tenantID)
	setDefault(values, "response_type", "code")
	setDefault(values, "redirect_uri", joinURL(c.appURL, "/v2/api/fusionauth/login").String())
	setDefault(values, "timezone", "UTC")
	values.Set("metaData.device.name", "Gluetun")
	values.Set("metaData.device.type", "BROWSER")
	values.Set("showPasswordField", "true")
	values.Set("loginId", c.credentials.Username)
	values.Set("password", c.credentials.Password)
	return c.submitForm(ctx, page, loginForm, values)
}

// submitTwoFactorCode submits the two-factor code generated from the
// TOTP secret. If the code is rejected, which can happen if it was
// generated at the end of its time step or was already used, it waits
// for the next time step and submits the next code once.
func (c *Client) submitTwoFactorCode(ctx context.Context, page *htmlPage) (*htmlPage, error) {
	if c.credentials.TOTPSecret == "" {
		return nil, errTwoFactorRequired
	}

	now := c.timeNow()
	page, err := c.submitTwoFactorCodeAt(ctx, page, now)
	if err != nil {
		return nil, err
	}
	// The two-factor code form is shown again if the code is rejected.
	if page.findForm(isTwoFactorForm) == nil {
		return page, nil
	}

	// TOTP codes from authenticator apps change every 30 seconds.
	const timeStepSeconds = 30
	nextTimeStep := time.Unix((now.Unix()/timeStepSeconds+1)*timeStepSeconds, 0)
	err = waitFor(ctx, nextTimeStep.Sub(now))
	if err != nil {
		return nil, fmt.Errorf("waiting for the next two-factor code: %w", err)
	}

	page, err = c.submitTwoFactorCodeAt(ctx, page, nextTimeStep)
	if err != nil {
		return nil, err
	}
	if page.findForm(isTwoFactorForm) != nil {
		return nil, fmt.Errorf("%w: %s", errTwoFactorCodeInvalid, page.errorMessage())
	}
	return page, nil
}

func (c *Client) submitTwoFactorCodeAt(ctx context.Context, page *htmlPage,
	codeTime time.Time,
) (*htmlPage, error) {
	code, err := totpCode(c.credentials.TOTPSecret, codeTime)
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
	return page, nil
}

// waitFor waits for the duration given or until the context is canceled.
func waitFor(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		timer.Stop()
		return ctx.Err()
	}
}

func totpCode(secret string, now time.Time) (code string, err error) {
	// The padding is removed since the library adds its own padding
	// to the secret, and it uppercases the secret.
	secret = strings.TrimRight(strings.ReplaceAll(secret, " ", ""), "=")
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
	// The form action comes from the page, and must not
	// send the credentials to another host.
	if action.Scheme != c.authURL.Scheme || action.Host != c.authURL.Host {
		return nil, fmt.Errorf("form action: %w: %s", errHostNotAllowed, action.Host)
	}
	return c.doAuthRequest(ctx, http.MethodPost, action.String(), values)
}

// doAuthRequest does a request to the auth server, following redirects
// until the access token cookie is set, and returns the final HTML page.
func (c *Client) doAuthRequest(ctx context.Context, method, rawURL string,
	form url.Values,
) (page *htmlPage, err error) {
	request, err := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(form.Encode()))
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

	page = &htmlPage{url: response.Request.URL, status: response.Status}
	if c.getAccessTokenCookie() != "" {
		// Logged in, the final page content does not matter, and it
		// can be a redirect response or a Cloudflare challenge page.
		return page, nil
	}

	err = checkBlocked(response, responseBody)
	if err != nil {
		return nil, err
	}

	if response.StatusCode >= http.StatusInternalServerError {
		return nil, fmt.Errorf("%w: %s returned %s",
			errUnexpectedResponse, redactURL(response.Request.URL), response.Status)
	}

	page.forms, page.errors = parseHTML(responseBody)
	return page, nil
}

type htmlPage struct {
	url *url.URL
	// status is the HTTP status of the page response, such as "200 OK".
	status string
	forms  []*htmlForm
	errors []string
}

type htmlForm struct {
	action string
	inputs []htmlInput
}

type htmlInput struct {
	name      string
	value     string
	inputType string
	checked   bool
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

// values returns the form values, excluding unchecked
// checkboxes, and submit and other buttons.
func (f *htmlForm) values() url.Values {
	values := url.Values{}
	for _, input := range f.inputs {
		switch {
		case input.name == "",
			input.inputType == "submit", input.inputType == "button",
			input.inputType == "checkbox" && !input.checked:
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

// parseHTML extracts the forms and the error messages from an HTML page.
// FusionAuth themes show errors in elements with an "error" class or
// an "alert" role.
func parseHTML(body []byte) (forms []*htmlForm, errorMessages []string) {
	root, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, nil
	}

	parser := &htmlParser{}
	parser.walk(root, false, false)
	return parser.forms, parser.errorMessages
}

type htmlParser struct {
	forms         []*htmlForm
	currentForm   *htmlForm
	errorMessages []string
}

// walk walks the HTML node tree. insideError is true if an ancestor
// is an error element, whose text content was already collected, and
// hidden is true if the node or an ancestor is hidden.
func (p *htmlParser) walk(node *html.Node, insideError, hidden bool) {
	if node.Type == html.ElementNode {
		hidden = hidden || isHiddenElement(node)
		p.handleElement(node)
		if !insideError && !hidden && isErrorElement(node) {
			insideError = true
			text := strings.Join(strings.Fields(textContent(node)), " ")
			if text != "" {
				p.errorMessages = append(p.errorMessages, text)
			}
		}
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		p.walk(child, insideError, hidden)
	}
	if node.Type == html.ElementNode && node.Data == "form" {
		// Inputs after the end of the form are not part of it.
		// Forms cannot be nested, the HTML parser drops inner forms.
		p.currentForm = nil
	}
}

func (p *htmlParser) handleElement(node *html.Node) {
	switch node.Data {
	case "form":
		p.currentForm = &htmlForm{action: attribute(node, "action")}
		p.forms = append(p.forms, p.currentForm)
	case "input", "button":
		if p.currentForm == nil {
			return
		}
		_, checked := attributeExists(node, "checked")
		inputType := strings.ToLower(attribute(node, "type"))
		if inputType == "" && node.Data != "input" {
			inputType = "submit" // a button without type is a submit button
		}
		p.currentForm.inputs = append(p.currentForm.inputs, htmlInput{
			name:      attribute(node, "name"),
			value:     attribute(node, "value"),
			inputType: inputType,
			checked:   checked,
		})
	}
}

// isHiddenElement returns true if the element is not displayed,
// such as template elements or elements hidden with an attribute
// or an inline style.
func isHiddenElement(node *html.Node) bool {
	switch node.Data {
	case "template", "script", "style", "noscript":
		return true
	}
	_, hidden := attributeExists(node, "hidden")
	if hidden || attribute(node, "aria-hidden") == "true" {
		return true
	}
	style := strings.ReplaceAll(strings.ToLower(attribute(node, "style")), " ", "")
	return strings.Contains(style, "display:none") || strings.Contains(style, "visibility:hidden")
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
	for _, nodeAttribute := range node.Attr {
		if nodeAttribute.Key == key {
			return nodeAttribute.Val, true
		}
	}
	return "", false
}

func textContent(node *html.Node) string {
	var builder strings.Builder
	var walk func(node *html.Node)
	walk = func(node *html.Node) {
		switch {
		case node.Type == html.ElementNode && isHiddenElement(node):
			return
		case node.Type == html.TextNode:
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
