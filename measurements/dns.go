package measurements

import (
	"fmt"

	"github.com/miekg/dns"
	//	"netiscope/util"
)

// QueryDNSResolvers handles a DNS query/response against a particular resolver
// target is the name to look up
// qType is either A or AAAA
// server is the resolver we're asking
// @return:
// a list of results (IPs or CNAMES perhaps)
// some stats about the query
// error code
func QueryDNSResolvers(target string, qType string, server string) (result []string, stats string, dnserror error) {

	result = make([]string, 0, 100)
	dnserror = nil
	server = "[" + server + "]:53"

	c := new(dns.Client)

	c.Net = "udp"
	/*
		if *four {
			c.Net = "udp4"
		}
		if *six {
			c.Net = "udp6"
		}
	*/

	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: make([]dns.Question, 1),
	}
	m.Rcode = dns.RcodeSuccess

	qt := dns.TypeA
	if qType == "AAAA" {
		qt = dns.TypeAAAA
	}
	qc := uint16(dns.ClassINET)

	m.Question[0] = dns.Question{Name: dns.Fqdn(target), Qtype: qt, Qclass: qc}
	m.Id = dns.Id()
	r, rtt, err := c.Exchange(m, server)
	if err != nil {
		dnserror = err
		return
	}
	if r.Id != m.Id {
		dnserror = fmt.Errorf("DNS ID mismatch (%v vs %v)", r.Id, m.Id)
		return
	}
	if r.Rcode != dns.RcodeSuccess {
		dnserror = fmt.Errorf("DNS response error (%v)", dns.RcodeToString[r.Rcode])
		return
	}

	for _, answer := range r.Answer {
		switch t := answer.(type) {
		case *dns.A:
			if qt == dns.TypeA {
				result = append(result, t.A.String())
			}
		case *dns.AAAA:
			if qt == dns.TypeAAAA {
				result = append(result, t.AAAA.String())
			}
		}
	}
	stats = fmt.Sprintf("Query time: %v, server: %s (%s), size: %d bytes", rtt, server, c.Net, r.Len())

	return
}
