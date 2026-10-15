package wgapi

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
)

// cookieJar is a cookie jar which drops a cookie restored from
// the session as soon as a server sets a cookie with the same name.
// Restored cookies are host-only with the path "/", so without this,
// a server cookie with the same name but a Domain attribute or another
// path would be stored next to the stale restored cookie.
type cookieJar struct {
	jar     *cookiejar.Jar
	authURL *url.URL

	mutex    sync.Mutex
	restored map[string]struct{}
}

func newCookieJar(authURL *url.URL) (jar *cookieJar, err error) {
	innerJar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &cookieJar{
		jar:      innerJar,
		authURL:  authURL,
		restored: make(map[string]struct{}),
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
		j.restored[name] = struct{}{}
	}
	j.jar.SetCookies(j.authURL, cookies)
}

func (j *cookieJar) SetCookies(requestURL *url.URL, cookies []*http.Cookie) {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	var expired []*http.Cookie
	for _, cookie := range cookies {
		_, isRestored := j.restored[cookie.Name]
		if !isRestored {
			continue
		}
		delete(j.restored, cookie.Name)
		expired = append(expired, &http.Cookie{Name: cookie.Name, Path: "/", MaxAge: -1})
	}
	if len(expired) > 0 {
		j.jar.SetCookies(j.authURL, expired)
	}
	j.jar.SetCookies(requestURL, cookies)
}

func (j *cookieJar) Cookies(requestURL *url.URL) []*http.Cookie {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.jar.Cookies(requestURL)
}
