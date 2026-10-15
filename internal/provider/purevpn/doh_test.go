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

func Test_extractIPv4s(t *testing.T) {
	t.Parallel()

	newQuery := func() *dns.Msg {
		query := new(dns.Msg)
		query.SetQuestion("host.example.com.", dns.TypeA)
		query.Id = 0
		return query
	}
	aRecord := func(name string, ip net.IP) *dns.A {
		return &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: ip}
	}
	cnameRecord := func(name, target string) *dns.CNAME {
		return &dns.CNAME{
			Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: target,
		}
	}
	ip1 := net.IPv4(203, 0, 113, 1)
	ip2 := net.IPv4(203, 0, 113, 2)

	testCases := map[string]struct {
		modify     func(answer *dns.Msg)
		ips        []netip.Addr
		errMessage string
	}{
		"a_record": {
			modify: func(answer *dns.Msg) {
				answer.Answer = []dns.RR{aRecord("host.example.com.", ip1)}
			},
			ips: []netip.Addr{netip.MustParseAddr("203.0.113.1")},
		},
		"case_insensitive_names": {
			modify: func(answer *dns.Msg) {
				answer.Question[0].Name = "HOST.example.com."
				answer.Answer = []dns.RR{
					cnameRecord("Host.Example.com.", "CDN.example.com."),
					aRecord("cdn.EXAMPLE.com.", ip1),
				}
			},
			ips: []netip.Addr{netip.MustParseAddr("203.0.113.1")},
		},
		"unordered_cname_chain": {
			modify: func(answer *dns.Msg) {
				answer.Answer = []dns.RR{
					aRecord("edge.example.net.", ip1),
					cnameRecord("cdn.example.com.", "edge.example.net."),
					aRecord("other.example.com.", ip2),
					cnameRecord("host.example.com.", "cdn.example.com."),
				}
			},
			ips: []netip.Addr{netip.MustParseAddr("203.0.113.1")},
		},
		"cname_loop": {
			modify: func(answer *dns.Msg) {
				answer.Answer = []dns.RR{
					cnameRecord("host.example.com.", "cdn.example.com."),
					cnameRecord("cdn.example.com.", "host.example.com."),
					aRecord("other.example.com.", ip2),
				}
			},
			errMessage: "no IPv4 address found",
		},
		"a_record_for_other_name": {
			modify: func(answer *dns.Msg) {
				answer.Answer = []dns.RR{
					aRecord("other.example.com.", ip2),
					aRecord("host.example.com.", ip1),
				}
			},
			ips: []netip.Addr{netip.MustParseAddr("203.0.113.1")},
		},
		"only_a_record_for_other_name": {
			modify: func(answer *dns.Msg) {
				answer.Answer = []dns.RR{aRecord("other.example.com.", ip2)}
			},
			errMessage: "no IPv4 address found",
		},
		"invalid_a_record_ip": {
			modify: func(answer *dns.Msg) {
				answer.Answer = []dns.RR{aRecord("host.example.com.", nil)}
			},
			errMessage: "no IPv4 address found",
		},
		"id_mismatch": {
			modify: func(answer *dns.Msg) {
				answer.Id = 1
				answer.Answer = []dns.RR{aRecord("host.example.com.", ip1)}
			},
			errMessage: "DNS response ID 1 does not match query ID 0",
		},
		"not_a_response": {
			modify: func(answer *dns.Msg) {
				answer.Response = false
				answer.Answer = []dns.RR{aRecord("host.example.com.", ip1)}
			},
			errMessage: "DNS message is not a response",
		},
		"rcode_not_success": {
			modify: func(answer *dns.Msg) {
				answer.Rcode = dns.RcodeServerFailure
			},
			errMessage: "DNS response code is not success: SERVFAIL",
		},
		"no_question": {
			modify: func(answer *dns.Msg) {
				answer.Question = nil
				answer.Answer = []dns.RR{aRecord("host.example.com.", ip1)}
			},
			errMessage: "DNS response has 0 questions instead of 1",
		},
		"question_name_mismatch": {
			modify: func(answer *dns.Msg) {
				answer.Question[0].Name = "other.example.com."
				answer.Answer = []dns.RR{aRecord("other.example.com.", ip1)}
			},
			errMessage: "DNS response question \";other.example.com.\\tIN\\t A\" does not match " +
				"query question \";host.example.com.\\tIN\\t A\"",
		},
		"question_type_mismatch": {
			modify: func(answer *dns.Msg) {
				answer.Question[0].Qtype = dns.TypeAAAA
				answer.Answer = []dns.RR{aRecord("host.example.com.", ip1)}
			},
			errMessage: "DNS response question \";host.example.com.\\tIN\\t AAAA\" does not match",
		},
		"question_class_mismatch": {
			modify: func(answer *dns.Msg) {
				answer.Question[0].Qclass = dns.ClassCHAOS
				answer.Answer = []dns.RR{aRecord("host.example.com.", ip1)}
			},
			errMessage: "DNS response question \";host.example.com.\\tCH\\t A\" does not match",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			query := newQuery()
			answer := new(dns.Msg)
			answer.SetReply(query)
			testCase.modify(answer)

			ips, err := extractIPv4s(query, answer)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, testCase.ips, ips)
		})
	}
}
