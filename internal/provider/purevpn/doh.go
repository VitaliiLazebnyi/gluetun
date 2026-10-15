package purevpn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"

	"github.com/miekg/dns"
)

// dohResolver resolves hostnames using DNS over HTTPS (RFC 8484).
// It is used instead of the DNS over HTTPS dialer of github.com/qdm12/dns
// since its HTTP client must dial using marked sockets.
type dohResolver struct {
	// client is the HTTP client to reach the DNS over HTTPS servers.
	client *http.Client
	// urls are the DNS over HTTPS URLs to try in order.
	urls []string
}

// lookupIPv4 returns the IPv4 addresses of the host given,
// trying each DNS over HTTPS server until one succeeds.
func (r *dohResolver) lookupIPv4(ctx context.Context, host string) (ips []netip.Addr, err error) {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(host), dns.TypeA)
	query.Id = 0 // RFC 8484 section 4.1 recommends an ID of 0
	packedQuery, err := query.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing DNS query: %w", err)
	}

	errs := make([]error, 0, len(r.urls))
	for _, dohURL := range r.urls {
		ips, err = queryDoH(ctx, r.client, dohURL, packedQuery)
		if err == nil {
			return ips, nil
		}
		errs = append(errs, fmt.Errorf("querying %s: %w", dohURL, err))
	}
	return nil, errors.Join(errs...)
}

func queryDoH(ctx context.Context, client *http.Client,
	dohURL string, packedQuery []byte,
) (ips []netip.Addr, err error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(packedQuery))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	const mediaType = "application/dns-message"
	request.Header.Set("Content-Type", mediaType)
	request.Header.Set("Accept", mediaType)

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("doing request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status code is not OK: %d %s",
			response.StatusCode, response.Status)
	}

	const maxDNSMessageSize = 65535
	body, err := io.ReadAll(io.LimitReader(response.Body, maxDNSMessageSize))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	answer := new(dns.Msg)
	err = answer.Unpack(body)
	if err != nil {
		return nil, fmt.Errorf("unpacking DNS response: %w", err)
	}
	if answer.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS response code is not success: %s", dns.RcodeToString[answer.Rcode])
	}

	for _, record := range answer.Answer {
		aRecord, ok := record.(*dns.A)
		if !ok {
			continue // for example a CNAME record
		}
		ip, ok := netip.AddrFromSlice(aRecord.A)
		if !ok {
			continue
		}
		ips = append(ips, ip.Unmap())
	}
	if len(ips) == 0 {
		return nil, errors.New("no IPv4 address found")
	}
	return ips, nil
}
