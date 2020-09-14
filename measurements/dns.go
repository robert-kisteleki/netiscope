package measurements

import (
	"fmt"
	"net"
	"netiscope/util"
	"strings"

	"github.com/miekg/dns"
)

// DNSQuery handles a DNS query/response against a particular server/resolver
// much of this is reused from the examples in https://github.com/miekg/exdns/
// target: is the name to look up
// qType: is either A or AAAA
// server: is the resolver we're asking
// nsid: ask for NSID?
// rd: ask for recursion?
// @return:
// result: a list of results and options (IPs or SOA or NSID records and such)
// error code upon error
func DNSQuery(
	check string,
	target string,
	qType string,
	server string,
	nsid bool,
	rd bool,
) (result map[string][]string, dnserror error) {

	// TODO the result is not really flexible enough
	result = make(map[string][]string)
	dnserror = nil
	server = net.JoinHostPort(server, "53")

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
			RecursionDesired: rd,
		},
		Question: make([]dns.Question, 1),
	}
	m.Rcode = dns.RcodeSuccess

	qt := dns.TypeA
	qc := dns.ClassINET
	switch qType {
	case "A":
		qt = dns.TypeA
	case "AAAA":
		qt = dns.TypeAAAA
	case "TXT":
		qt = dns.TypeTXT
		qc = dns.ClassCHAOS
	case "SOA":
		qt = dns.TypeSOA
	case "NS":
		qt = dns.TypeNS
	default:
		util.Log("DNS", util.LevelFatal, "DNS", fmt.Sprintf("Don't know how to query DNS for %s", qType))
		panic(1)
	}

	// NSID
	if nsid {
		o := &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
			},
		}
		e := &dns.EDNS0_NSID{
			Code: dns.EDNS0NSID,
		}
		o.Option = append(o.Option, e)
		o.SetUDPSize(dns.DefaultMsgSize)
		m.Extra = append(m.Extra, o)
	}

	m.Question[0] = dns.Question{Name: dns.Fqdn(target), Qtype: qt, Qclass: uint16(qc)}
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
				result["A"] = append(result["A"], t.A.String())
			}
		case *dns.AAAA:
			if qt == dns.TypeAAAA {
				result["AAAA"] = append(result["AAAA"], t.AAAA.String())
			}
		case *dns.SOA:
			if qt == dns.TypeSOA {
				result["SOA"] = append(result["SOA"], fmt.Sprintf("%s %d", t.Ns, t.Serial))
			}
		default:
			util.Log("DNS", util.LevelFatal, "DNS", fmt.Sprintf("Don't know how to handle result type %v", t))
			panic(1)
		}
	}

	for _, answer := range r.Ns {
		switch t := answer.(type) {
		case *dns.NS:
			if qt == dns.TypeNS {
				result["NS"] = append(result["NS"], t.Ns)
			}
		}
	}

	if nsid {
		for _, extra := range r.Extra {
			// TODO find a way to extract NSID more elegantly than this hack
			s := extra.String()
			for _, line := range strings.Split(s, "\n") {
				if strings.HasPrefix(line, "; NSID:") {
					for _, token := range strings.Split(line, " ") {
						if strings.HasPrefix(token, "(") {
							s1 := strings.ReplaceAll(token, "(", "")
							s2 := strings.ReplaceAll(s1, ")", "")
							result["NSID"] = append(result["NSID"], s2)
						}
					}
				}
			}
		}
	}

	stats := fmt.Sprintf("Query time: %v, server: %s (%s), size: %d bytes", rtt, server, c.Net, r.Len())
	util.Log(check, util.LevelDetail, "DNS_QUERY_STATS", stats)

	return
}
