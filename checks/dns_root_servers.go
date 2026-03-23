package checks

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"netiscope/util"
)

// CheckDNSRootServers checks all DNS root servers
type DNSRootServersCheck struct {
	netiscopeCheckBase
}

type rootDNSServerCheckType struct {
	Letter    string
	IPv4      string
	IPv6      string
	Pingable4 bool
	Pingable6 bool
}

// these really don't change too often
var rootDNSServers []rootDNSServerCheckType

// Start executes the DNS root server check
func (check *DNSRootServersCheck) start() {
	check.netiscopeCheckBase.start()

	for _, server := range rootDNSServers {
		if check.stopping {
			break
		}
		if !util.SkipIPv4() {
			checkRootDNSServer(&check.netiscopeCheckBase, server.Letter, "IPv4", server.IPv4, server.Pingable4)
		}
		if !util.SkipIPv6() {
			checkRootDNSServer(&check.netiscopeCheckBase, server.Letter, "IPv6", server.IPv6, server.Pingable6)
		}
	}

	// TODO: compare responses from different root servers?

	check.netiscopeCheckBase.finish()
}

func (check *DNSRootServersCheck) configure() {
	for _, item := range util.LoadRootDNSServerData() {
		if len(item) < 3 {
			check.log(
				LogLevelError,
				"DNS_ROOT_SERVER_CONFIG_ERROR",
				fmt.Sprintf(
					"Wrong configuration item for DNS root server check: %v",
					item,
				),
			)
		}
		root := rootDNSServerCheckType{
			Letter:    item[0],
			IPv4:      item[1],
			IPv6:      item[2],
			Pingable4: len(item) < 5 || item[3] == "true",
			Pingable6: len(item) < 5 || item[4] == "true",
		}
		rootDNSServers = append(rootDNSServers, root)
	}
}

// check a particular DNS root server on IPv4 or IPv6
// letter: which root DNS server to test ([A..M])
// af: address family (IPv4 or IPv6)
// server: the server's address
func checkRootDNSServer(
	check *netiscopeCheckBase,
	letter string,
	af string,
	server string,
	pingable bool,
) {
	check.log(
		LogLevelInfo,
		"CKECKING_DNS_ROOT_SERVER",
		fmt.Sprintf(
			"Checking %s-root %s server %v",
			letter, af, server,
		),
	)
	testRootDNSServerOnAddressFamily(check, letter, af, server, pingable)
}

// test a root DNS server on a particular address family
// letter: which root DNS server to test ([A..M])
// af: address family (IPv4 or IPv6)
// server: the server's address
func testRootDNSServerOnAddressFamily(
	check *netiscopeCheckBase,
	letter string,
	af string,
	server string,
	pingable bool,
) {
	if pingable && shouldCheckDNSFunction("ping") {
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
	check *netiscopeCheckBase,
	letter string,
	af string,
	server string,
) (out MultipleResult) {

	// ask one server for a SOA record and check sanity of the result
	check.log(
		LogLevelInfo,
		"ROOT_DNS_SERVER_SOA_QUERY",
		fmt.Sprintf("Querying SOA record from %s-root server %s", letter, server),
	)

	answers, err := DNSQuery(check, ".", "SOA", server, true, false, true, false)
	if err != nil {
		check.log(LogLevelError, "ROOT_DNS_SERVER_SOA", err.Error())
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
			check.log(
				LogLevelInfo, "ROOT_DNS_SERVER_SOA_SERIAL",
				fmt.Sprintf("SOA serial is %s", serial),
			)
			out[ResultSuccess]++
		} else {
			check.log(
				LogLevelWarning, "ROOT_DNS_SERVER_SOA_OLD",
				fmt.Sprintf("SOA serial %s is too old?", serial),
			)
			out[ResultFailure]++
		}
	}

	// report NSID
	for _, answer := range answers["NSID"] {
		check.log(
			LogLevelInfo, "ROOT_DNS_SERVER_NSID",
			fmt.Sprintf("NSID of DNS response is %s", answer),
		)
	}

	// ask for some TLDs and check sanity of the results

	// the TLDs to look up are in the config file
	tlds := util.GetTLDsToLookup()
	if len(tlds) == 0 {
		check.log(LogLevelFatal, "ROOT_NO_TLDS", "The list of TLDs to look up is empty")
	}

	// look up the predefined TLDs
	for _, tld := range tlds {
		check.log(
			LogLevelInfo,
			"ROOT_DNS_SERVER_TLD_QUERY",
			fmt.Sprintf("Querying TLD %s from %s-root server %s", tld, letter, server),
		)

		answers, err := DNSQuery(check, tld+".", "NS", server, true, false, true, false)
		if err != nil {
			check.log(LogLevelError, "ROOT_DNS_SERVER_TLD", err.Error())
			out[ResultFailure]++
		}

		check.log(
			LogLevelInfo,
			"ROOT_DNS_SERVER_TLD_NSSET",
			fmt.Sprintf("NS set for %s is %v", tld, answers["NS"]),
		)
		if len(answers["NS"]) < 4 {
			// TODO: better sanity check of answers
			check.log(
				LogLevelWarning,
				"ROOT_DNS_SERVER_NSSET_SHORT",
				fmt.Sprintf("NS set for %s is too short (%d)", tld, len(answers["NS"])),
			)
			out[ResultFailure]++
		}

		// report NSID
		for _, answer := range answers["NSID"] {
			check.log(LogLevelInfo, "ROOT_DNS_SERVER_NSID", fmt.Sprintf("NSID of DNS response is %s", answer))
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
		check.log(
			LogLevelInfo,
			"ROOT_DNS_SERVER_RANDOM_QUERY",
			fmt.Sprintf("Querying TLD %s from %s-root server %s", tld, letter, server),
		)

		answers, err := DNSQuery(check, tld+".", "NS", server, true, false, true, false)
		if err != nil {
			check.log(
				LogLevelDetail,
				"ROOT_DNS_SERVER_TLD_NXDOMAIN",
				fmt.Sprintf("Random TLD lookup for %s failed as expected", tld),
			)
			out[ResultSuccess]++
		} else {
			check.log(
				LogLevelError,
				"ROOT_DNS_SERVER_TLD_NSSET",
				fmt.Sprintf("NS set for %s is %v", tld, answers["NS"]),
			)
			out[ResultFailure]++
		}

		// report NSID
		for _, answer := range answers["NSID"] {
			check.log(
				LogLevelInfo,
				"ROOT_DNS_SERVER_NSID",
				fmt.Sprintf("NSID of DNS response is %s", answer),
			)
		}
	}

	return
}
