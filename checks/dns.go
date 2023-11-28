package checks

import (
	"fmt"
	"net"
	"netiscope/log"
	"strings"

	"github.com/miekg/dns"
)

/*
  the DNS checks are based on the excellent https://github.com/miekg/dns/ package
  much of the client code is reused from the examples in https://github.com/miekg/exdns/
*/

// DNSQuery handles a DNS query/response against a particular server/resolver
// target: is the name to look up
// qType: is either A or AAAA
// server: is the resolver we're asking
// nsid: ask for NSID?
// rd: ask for recursion?
// do: ask for DNSSEC validation?
// zeroID: set query ID to zero? usually no, but DoH prefers that
// @return:
// result: a list of results and options (IPs or SOA or NSID records and such)
// dnserror: code upon error
func DNSQuery(
	check log.Check,
	target string,
	qType string,
	server string,
	nsid bool,
	rd bool,
	do bool,
	zeroID bool,
) (result map[string][]string, dnserror error) {

	// TODO the result is not really flexible enough

	dnserror = nil
	server = net.JoinHostPort(server, "53")

	query := prepareDNSQuery(check, target, qType, nsid, rd, do, zeroID)

	c := new(dns.Client)
	c.Net = "udp"

	response, rtt, err := c.Exchange(&query, server)
	if err != nil {
		dnserror = err
		return
	}
	if response.Id != query.Id {
		dnserror = fmt.Errorf("DNS ID mismatch (%v vs %v)", response.Id, query.Id)
		return
	}
	if response.Rcode != dns.RcodeSuccess {
		dnserror = fmt.Errorf("DNS response error (%v)", dns.RcodeToString[response.Rcode])
		return
	}

	result = parseDNSResponse(check, response)

	stats := fmt.Sprintf("Query time: %v, server: %s (%s), size: %d bytes", rtt, server, c.Net, response.Len())
	log.NewResultItem(check, log.LevelDetail, "DNS_QUERY_STATS", stats)

	return
}

// CreateDNSQuery creates a DNS query and returns its on-the-wire encoding
// target: is the name to look up
// qType: is either A or AAAA
// nsid: ask for NSID?
// rd: ask for recursion?
// do: ask for DNSSEC OK?
// zeroID: use zero as query ID?
// @return: an assembled DNS query in on-the-wire format
func CreateDNSQuery(
	check log.Check,
	target string,
	qType string,
	nsid bool,
	rd bool,
	do bool,
	zeroID bool,
) []byte {

	query := prepareDNSQuery(check, target, qType, nsid, rd, do, zeroID)
	buf, _ := query.Pack()

	return buf
}

// ParseDNSResponse takes an on-the-wire response and extracts the results we're interested in
// responseBytes: on-the-wire DNS response to parse
// @return:
// result: a list of results and options (IPs or SOA or NSID records and such)
// error code upon error
func ParseDNSResponse(
	check log.Check,
	responseBytes []byte,
) (result map[string][]string, err error) {
	var response dns.Msg
	err = response.Unpack(responseBytes)
	if err != nil {
		return
	}

	result = parseDNSResponse(check, &response)
	return
}

// prepare a DNS query from a given set of parameters
// target: is the name to look up
// qType: is either A or AAAA
// nsid: ask for NSID?
// rd: ask for recursion?
// do: ask for DNSSEC OK?
// zeroID: use zero as query ID?
// @return: the DNS query (using the type of the underlying DNS package)
func prepareDNSQuery(
	check log.Check,
	target string,
	qType string,
	nsid bool,
	rd bool,
	do bool,
	zeroID bool,
) dns.Msg {

	query := dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: rd,
		},
		Question: make([]dns.Question, 1),
	}
	query.Rcode = dns.RcodeSuccess

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
		log.NewResultItem(check, log.LevelFatal, "DNS", fmt.Sprintf("Don't know how to query DNS for %s", qType))
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
		query.Extra = append(query.Extra, o)
	}

	query.Question[0] = dns.Question{Name: dns.Fqdn(target), Qtype: qt, Qclass: uint16(qc)}

	if !zeroID {
		query.Id = dns.Id()
	}

	return query
}

// parse a DNS response (using the type of the underlying DNS package)
// response: a DNS response to parse
// @return:
// result: a list of results and options (IPs or SOA or NSID records and such)
func parseDNSResponse(
	check log.Check,
	response *dns.Msg,
) (result map[string][]string) {
	result = make(map[string][]string)

	for _, answer := range response.Answer {
		switch t := answer.(type) {
		case *dns.A:
			result["A"] = append(result["A"], t.A.String())
		case *dns.AAAA:
			result["AAAA"] = append(result["AAAA"], t.AAAA.String())
		case *dns.SOA:
			result["SOA"] = append(result["SOA"], fmt.Sprintf("%s %d", t.Ns, t.Serial))
		default:
			log.NewResultItem(check, log.LevelFatal, "DNS", fmt.Sprintf("Don't know how to handle result type %v", t))
			panic(1)
		}
	}

	for _, answer := range response.Ns {
		switch t := answer.(type) {
		case *dns.NS:
			result["NS"] = append(result["NS"], t.Ns)
		}
	}

	for _, extra := range response.Extra {
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

	return result
}
