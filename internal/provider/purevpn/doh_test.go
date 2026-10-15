package purevpn

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_dohResolver_lookupIPv4(t *testing.T) {
	t.Parallel()

	answerWith := func(rcode int, records ...dns.RR) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			query := new(dns.Msg)
			err = query.Unpack(body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			answer := new(dns.Msg)
			answer.SetReply(query)
			answer.Rcode = rcode
			answer.Answer = records
			packed, err := answer.Pack()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(packed)
		}
	}
	header := func(rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: "host.example.com.", Rrtype: rrtype, Class: dns.ClassINET, Ttl: 60}
	}
	cname := &dns.CNAME{Hdr: header(dns.TypeCNAME), Target: "cdn.example.com."}
	aRecord := &dns.A{Hdr: header(dns.TypeA), A: net.IPv4(203, 0, 113, 7)}
	statusError := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	testCases := map[string]struct {
		handlers   []http.Handler
		ips        []netip.Addr
		errMessage string
	}{
		"cname_and_a_records": {
			handlers: []http.Handler{answerWith(dns.RcodeSuccess, cname, aRecord)},
			ips:      []netip.Addr{netip.MustParseAddr("203.0.113.7")},
		},
		"fallback_to_second_server": {
			handlers: []http.Handler{statusError, answerWith(dns.RcodeSuccess, aRecord)},
			ips:      []netip.Addr{netip.MustParseAddr("203.0.113.7")},
		},
		"name_error": {
			handlers:   []http.Handler{answerWith(dns.RcodeNameError)},
			errMessage: "DNS response code is not success: NXDOMAIN",
		},
		"no_a_record": {
			handlers:   []http.Handler{answerWith(dns.RcodeSuccess, cname)},
			errMessage: "no IPv4 address found",
		},
		"http_status_error": {
			handlers:   []http.Handler{statusError},
			errMessage: "HTTP status code is not OK: 500",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			urls := make([]string, len(testCase.handlers))
			for i, handler := range testCase.handlers {
				server := httptest.NewServer(handler)
				t.Cleanup(server.Close)
				urls[i] = server.URL + "/dns-query"
			}
			resolver := &dohResolver{
				client: &http.Client{Timeout: 5 * time.Second},
				urls:   urls,
			}

			ips, err := resolver.lookupIPv4(context.Background(), "host.example.com")

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.ips, ips)
		})
	}
}
