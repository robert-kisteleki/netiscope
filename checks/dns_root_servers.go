package checks

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"netiscope/log"
	"netiscope/util"
)

type serverAddress struct {
	v4 string
	v6 string
}
type rootDNSServer struct {
	letter    string
	addresses serverAddress
}

// these really don't change too often
var rootDNSServers = []rootDNSServer{
	{"A", serverAddress{"198.41.0.4", "2001:503:ba3e::2:30"}},   // Verisign, Inc.
	{"B", serverAddress{"170.247.170.2", "2801:1b8:10::b"}},     // Information Sciences Institute (ISI)
	{"C", serverAddress{"192.33.4.12", "2001:500:2::c"}},        // Cogent Communications
	{"D", serverAddress{"199.7.91.13", "2001:500:2d::d"}},       // University of Maryland
	{"E", serverAddress{"192.203.230.10", "2001:500:a8::e"}},    // NASA Ames Research Center
	{"F", serverAddress{"192.5.5.241", "2001:500:2f::f"}},       // Internet Systems Consortium, Inc. (ISC)
	{"G", serverAddress{"192.112.36.4", "2001:500:12::d0d"}},    // Defense Information Systems Agency
	{"H", serverAddress{"198.97.190.53", "2001:500:1::53"}},     // U.S. Army Research Lab
	{"I", serverAddress{"192.36.148.17", "2001:7fe::53"}},       // Netnod
	{"J", serverAddress{"192.58.128.30", "2001:503:c27::2:30"}}, // Verisign, Inc.
	{"K", serverAddress{"193.0.14.129", "2001:7fd::1"}},         // RIPE NCC
	{"L", serverAddress{"199.7.83.42", "2001:500:9f::42"}},      // ICANN
	{"M", serverAddress{"202.12.27.33", "2001:dc3::35"}},        // WIDE Project
}

// CheckDNSRootServers checks all DNS root servers
func CheckDNSRootServers(check *log.Check) {
	defer close(check.Tracker)
	for _, server := range rootDNSServers {
		if !util.SkipIPv4() {
			checkRootDNSServer(check, server.letter, "IPv4", server.addresses.v4)
		}
		if !util.SkipIPv6() {
			checkRootDNSServer(check, server.letter, "IPv6", server.addresses.v6)
		}
	}

	// TODO: compare responses from different root servers?

	log.NewResultItem(check, log.LevelAdmin, "FINISH", "Finished")
}

// check a particular DNS root server on IPv4 or IPv6
// letter: which root DNS server to test ([A..M])
// af: address family (IPv4 or IPv6)
// server: the server's address
func checkRootDNSServer(
	check *log.Check,
	letter string,
	af string,
	server string,
) {
	log.NewResultItem(
		check,
		log.LevelInfo,
		"CKECKING_DNS_ROOT_SERVER",
		fmt.Sprintf(
			"Checking %s-root %s server %v",
			letter, af, server,
		),
	)
	testRootDNSServerOnAddressFamily(check, letter, af, server)
}

// test a root DNS server on a particular address family
// letter: which root DNS server to test ([A..M])
// af: address family (IPv4 or IPv6)
// server: the server's address
func testRootDNSServerOnAddressFamily(
	check *log.Check,
	letter string,
	af string,
	server string,
) {
	if shouldCheckDNSFunction("ping") {
		reportResolversOnAddressFamily(
			check,
			"ROOT_DNS_SERVER", af, letter+"-root DNS server", "PING", "reachable", []string{server},
			PingServers(check, "ROOT", []string{server}),
		)
	}
	if shouldCheckDNSFunction("query") {
		reportResolversOnAddressFamily(
			check,
			"ROOT_DNS_SERVER", af, letter+"-root DNS server", "QUERY", "answering", []string{server},
			queryRootDNSServer(check, letter, af, server),
		)
	}
}

// query a root DNS server on IPv4 or IPv6
// letter: which root DNS server to test ([A..M])
// af: address family (IPv4 or IPv6)
// server: the server's address
// return a MultipleResult
func queryRootDNSServer(
	check *log.Check,
	letter string,
	af string,
	server string,
) (out MultipleResult) {

	// ask one server for a SOA record and check sanity of the result
	log.NewResultItem(
		check, log.LevelInfo, "ROOT_DNS_SERVER_SOA_QUERY",
		fmt.Sprintf("Querying SOA record from %s-root server %s", letter, server),
	)

	answers, err := DNSQuery(check, ".", "SOA", server, true, false, true, false)
	if err != nil {
		log.NewResultItem(check, log.LevelError, "ROOT_DNS_SERVER_SOA", err.Error())
		out[ResultFailure]++
	}

	// report SOA data
	for _, answer := range answers["SOA"] {
		values := strings.Split(answer, " ")
		serial := values[1]
		parsedSerial, _ := time.Parse("20060102", serial[0:8])
		parsedSerialUnix := parsedSerial.Unix()

		curTime := time.Now().Unix()

		// grace period for SOA serial is two days
		if curTime-parsedSerialUnix < 2*86400 {
			log.NewResultItem(
				check, log.LevelInfo, "ROOT_DNS_SERVER_SOA_SERIAL",
				fmt.Sprintf("SOA serial is %s", serial),
			)
			out[ResultSuccess]++
		} else {
			log.NewResultItem(
				check, log.LevelWarning, "ROOT_DNS_SERVER_SOA_OLD",
				fmt.Sprintf("SOA serial %s is too old?", serial),
			)
			out[ResultFailure]++
		}
	}

	// report NSID
	for _, answer := range answers["NSID"] {
		log.NewResultItem(
			check, log.LevelInfo, "ROOT_DNS_SERVER_NSID",
			fmt.Sprintf("NSID of DNS response is %s", answer),
		)
	}

	// ask for some TLDs and check sanity of the results

	// the TLDs to look up are in the config file
	tlds := util.GetTLDsToLookup()
	if len(tlds) == 0 {
		log.NewResultItem(
			check, log.LevelFatal, "ROOT_NO_TLDS",
			"The list of TLDs to look up is empty",
		)
	}

	// look up the predefined TLDs
	for _, tld := range tlds {
		log.NewResultItem(check, log.LevelInfo, "ROOT_DNS_SERVER_TLD_QUERY",
			fmt.Sprintf("Querying TLD %s from %s-root server %s", tld, letter, server),
		)

		answers, err := DNSQuery(check, tld+".", "NS", server, true, false, true, false)
		if err != nil {
			log.NewResultItem(check, log.LevelError, "ROOT_DNS_SERVER_TLD", err.Error())
			out[ResultFailure]++
		}

		log.NewResultItem(
			check, log.LevelInfo, "ROOT_DNS_SERVER_TLD_NSSET",
			fmt.Sprintf("NS set for %s is %v", tld, answers["NS"]),
		)
		if len(answers["NS"]) < 4 {
			// TODO: better sanity check of answers
			log.NewResultItem(
				check,
				log.LevelWarning,
				"ROOT_DNS_SERVER_NSSET_SHORT",
				fmt.Sprintf("NS set for %s is too short (%d)", tld, len(answers["NS"])),
			)
			out[ResultFailure]++
		}

		// report NSID
		for _, answer := range answers["NSID"] {
			log.NewResultItem(check, log.LevelInfo, "ROOT_DNS_SERVER_NSID",
				fmt.Sprintf("NSID of DNS response is %s", answer),
			)
		}
		out[ResultSuccess]++
	}

	// generate a few random TLD names
	var randomTLDs []string
	chars := []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	for i := 0; i < util.GetRandomTLDAmount(); i++ {
		var builder strings.Builder
		for i := 0; i < 12; i++ {
			builder.WriteRune(chars[rand.Intn(len(chars))])
		}
		randomTLDs = append(randomTLDs, builder.String())
	}

	// look up random TLDs
	for _, tld := range randomTLDs {
		log.NewResultItem(
			check, log.LevelInfo, "ROOT_DNS_SERVER_RANDOM_QUERY",
			fmt.Sprintf("Querying TLD %s from %s-root server %s", tld, letter, server),
		)

		answers, err := DNSQuery(check, tld+".", "NS", server, true, false, true, false)
		if err != nil {
			log.NewResultItem(check, log.LevelDetail, "ROOT_DNS_SERVER_TLD_NXDOMAIN",
				fmt.Sprintf("Random TLD lookup for %s failed as expected", tld),
			)
			out[ResultSuccess]++
		} else {
			log.NewResultItem(
				check, log.LevelError, "ROOT_DNS_SERVER_TLD_NSSET",
				fmt.Sprintf("NS set for %s is %v", tld, answers["NS"]),
			)
			out[ResultFailure]++
		}

		// report NSID
		for _, answer := range answers["NSID"] {
			log.NewResultItem(
				check, log.LevelInfo, "ROOT_DNS_SERVER_NSID",
				fmt.Sprintf("NSID of DNS response is %s", answer),
			)
		}
	}

	return
}
