package wgapi

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"strings"
	"sync"
)

// cookieJar is a cookie jar which drops a cookie restored from the
// session as soon as the auth server sets a cookie with the same name.
// Restored cookies are host-only with the path "/", so without this,
// a server cookie with the same name but a Domain attribute or another
// path would be stored next to the stale restored cookie.
type cookieJar struct {
	jar     *cookiejar.Jar
	authURL *url.URL

	mutex sync.Mutex
	// restored maps the name of each restored cookie,
	// not yet replaced by the auth server, to its value.
	restored map[string]string
}

func newCookieJar(authURL *url.URL) (jar *cookieJar, err error) {
	innerJar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("creating inner cookie jar: %w", err)
	}
	return &cookieJar{
		jar:      innerJar,
		authURL:  authURL,
		restored: make(map[string]string),
	}, nil
}

// restore sets the auth cookies given as host-only cookies
// with the path "/" for the auth URL.
func (j *cookieJar) restore(authCookies map[string]string) {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	cookies := make([]*http.Cookie, 0, len(authCookies))
	for name, value := range authCookies {
		cookies = append(cookies, &http.Cookie{Name: name, Value: value, Path: "/"})
		j.restored[name] = value
	}
	j.jar.SetCookies(j.authURL, cookies)
}

func (j *cookieJar) SetCookies(requestURL *url.URL, cookies []*http.Cookie) {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	j.jar.SetCookies(requestURL, cookies)
	if requestURL.Hostname() != j.authURL.Hostname() {
		return
	}

	var expired []*http.Cookie
	for _, cookie := range cookies {
		restoredValue, isRestored := j.restored[cookie.Name]
		if !isRestored || cookie.Value == restoredValue {
			// A cookie with the restored value cannot be told apart
			// from the restored cookie, but keeping both is harmless.
			continue
		}
		cookiePath := effectiveCookiePath(requestURL, cookie)
		if !j.stored(requestURL, cookiePath, cookie) {
			continue
		}
		delete(j.restored, cookie.Name)
		if cookie.Domain == "" && cookiePath == "/" {
			// The server cookie replaced the restored cookie.
			continue
		}
		expired = append(expired, &http.Cookie{Name: cookie.Name, Path: "/", MaxAge: -1})
	}
	if len(expired) > 0 {
		j.jar.SetCookies(j.authURL, expired)
	}
}

// stored returns true if the inner jar holds the cookie given,
// which is not the case if the jar rejected it.
func (j *cookieJar) stored(requestURL *url.URL, cookiePath string, cookie *http.Cookie) bool {
	cookieURL := &url.URL{Scheme: requestURL.Scheme, Host: requestURL.Host, Path: cookiePath}
	for _, storedCookie := range j.jar.Cookies(cookieURL) {
		if storedCookie.Name == cookie.Name && storedCookie.Value == cookie.Value {
			return true
		}
	}
	return false
}

// effectiveCookiePath returns the path the cookie jar uses to store
// the cookie given, following RFC 6265 section 5.1.4.
func effectiveCookiePath(requestURL *url.URL, cookie *http.Cookie) string {
	switch {
	case strings.HasPrefix(cookie.Path, "/"):
		return cookie.Path
	case !strings.HasPrefix(requestURL.Path, "/"):
		return "/"
	default:
		return path.Dir(requestURL.Path)
	}
}

func (j *cookieJar) Cookies(requestURL *url.URL) []*http.Cookie {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.jar.Cookies(requestURL)
}
