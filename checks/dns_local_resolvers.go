package checks

import (
	"bufio"
	"fmt"
	"time"

	"os"
	"strings"

	"netiscope/measurements"
	"netiscope/util"
)

// resolv.conf parse results
var (
	rcDomain      string
	rcResolversV4 []string
	rcResolversV6 []string
	rcSearch      []string
)

type multipleResult [3]int

const (
	resultSuccess = 0
	resultPartial = 1
	resultFailure = 2
)

// CheckDNSResolvers ...
func CheckDNSResolvers() {

	if !loadResolvers() {
		util.Log(checkName, util.LevelError, "NO_RESOLV_CONF", "Could not load DNS resolver data from resolv.conf")
		return
	}

	testResolvers()
}

// read and collect useful entries from resolv.conf
// return: success or not
func loadResolvers() bool {
	resolvconf, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return false
	}

	rcstat, err := resolvconf.Stat()
	if err != nil {
		return false
	}
	util.Log(
		checkName,
		util.LevelInfo,
		"RESOLVCONF_DATE",
		fmt.Sprintf("resolf.conf was last modified %s ago (at %s)",
			util.DurationToHuman(time.Since(rcstat.ModTime())),
			rcstat.ModTime().Format(time.RFC3339),
		),
	)

	scanner := bufio.NewScanner(resolvconf)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "domain") {
			rcDomain = strings.Fields(line)[1]
		} else if strings.HasPrefix(line, "nameserver") {
			resolver := strings.Fields(line)[1]
			if util.IsIPv6(resolver) {
				rcResolversV6 = append(rcResolversV6, resolver)
			} else {
				rcResolversV4 = append(rcResolversV4, resolver)
			}
		} else if strings.HasPrefix(line, "search") {
			rcSearch = append(rcSearch, strings.Fields(line)[1])
		}
	}

	util.Log(checkName, util.LevelInfo, "DOMAIN", fmt.Sprintf("Current domain is: %s", rcDomain))
	if !util.SkipIPv4() {
		util.Log(checkName, util.LevelInfo, "RESOLVERS", fmt.Sprintf("IPv4 resolvers: %s", rcResolversV4))
	}
	if !util.SkipIPv6() {
		util.Log(checkName, util.LevelInfo, "RESOLVERS", fmt.Sprintf("IPv6 resolvers: %s", rcResolversV6))
	}
	util.Log(checkName, util.LevelInfo, "SEARCH", fmt.Sprintf("Search path: %s", rcSearch))

	return true
}

func testResolvers() {
	var pingV4, pingV6 multipleResult
	var queryV4, queryV6 multipleResult

	if len(rcResolversV4) == 0 && len(rcResolversV6) == 0 {
		util.Log(checkName, util.LevelError, "NO_RESOLVERS", "No resolvers defined in resolv.conf")
		return
	}

	// ping them
	if util.GetConfigBoolParam("dns_local_resolvers", "ping", false) {

		if !util.SkipIPv4() {
			pingV4 = pingResolvers(rcResolversV4)
		}
		if !util.SkipIPv6() {
			pingV6 = pingResolvers(rcResolversV6)
		}

		if len(rcResolversV4)+len(rcResolversV6) > 0 &&
			pingV4[resultSuccess]+pingV6[resultSuccess] == 0 {
			// all resolvers are unreachable
			util.Log(checkName, util.LevelWarning, "ALL_PING_FAIL", "All local DNS resolvers are unreachable")
			return
		}
	}

	// query them
	if util.GetConfigBoolParam("dns_local_resolvers", "query", false) {
		if !util.SkipIPv4() {
			queryV4 = queryResolvers(rcResolversV4)
		}
		if !util.SkipIPv6() {
			queryV6 = queryResolvers(rcResolversV6)
		}

		// draw conclusion
		if len(rcResolversV4)+len(rcResolversV6) > 0 &&
			queryV4[resultSuccess]+queryV6[resultSuccess] == 0 {
			// no resolvers gave answers
			util.Log(checkName, util.LevelError, "ALL_QUERY_FAIL", "No local DNS resolvers are answering queries")
			return
		}
	}
}

// ping resolvers
// return tuple of [#success, #partial, #fail]
func pingResolvers(resolvers []string) (results multipleResult) {
	for _, resolver := range resolvers {
		util.Log(
			checkName,
			util.LevelInfo,
			"PING_RESOLVER",
			fmt.Sprintf("Pinging resolver %s", resolver),
		)
		loss := measurements.Ping(checkName, resolver)
		switch {
		case loss == 0.0:
			results[resultSuccess]++
			util.Log(
				checkName,
				util.LevelInfo,
				"PING_WORKS",
				fmt.Sprintf("Resolver %s is reachable", resolver),
			)
		case loss == 100.0:
			results[resultFailure]++
			util.Log(
				checkName,
				util.LevelWarning,
				"PING_FAILS",
				fmt.Sprintf("Resolver %s is not reachable", resolver),
			)
		default:
			results[resultPartial]++
			util.Log(
				checkName,
				util.LevelWarning,
				"PING_WARNING",
				fmt.Sprintf("Resolver %s is partially reachable", resolver),
			)
		}
	}

	return
}

// query some names from the resolvers
// return tuple of [#success, #partial, #fail]
func queryResolvers(resolvers []string) (results multipleResult) {
	for _, resolver := range resolvers {
		names := util.GetDNSNamesToLookup()
		var nsuccess, nfail int
		for _, name := range names {
			if queryResolver(name, resolver) {
				nsuccess++
			} else {
				nfail++
			}
		}
		switch {
		case nsuccess == 0 && nfail > 0:
			results[resultFailure]++
			util.Log(
				checkName,
				util.LevelError,
				"RESOLVER_FAILS",
				fmt.Sprintf("Resolver %s is not answering queries", resolver),
			)
		case nsuccess > 0 && nfail > 0:
			results[resultPartial]++
			util.Log(
				checkName,
				util.LevelWarning,
				"RESOLVER_FLAKY",
				fmt.Sprintf("Resolver %s is only answering some queries", resolver),
			)
		case nsuccess > 0 && nfail == 0:
			results[resultSuccess]++
			util.Log(
				checkName,
				util.LevelInfo,
				"RESOLVER_WORKS",
				fmt.Sprintf("Resolver %s is answering queries", resolver),
			)
		case nsuccess == 0 && nfail == 0:
			// there were no names on the list
		}
	}
	return
}

// ask one resolver for one query
// @return if it was successful
func queryResolver(name string, resolver string) bool {
	var answersA, answersAAAA []string
	var statsA, statsAAAA string
	var err error

	if !util.SkipIPv4() {
		answersA, statsA, err = measurements.QueryDNSResolvers(name, "A", resolver)
		if err != nil {
			util.Log(checkName, util.LevelError, "RESOLVER_ERROR_A", err.Error())
			return false
		}
		util.Log(checkName, util.LevelDetail, "RESOLVER_STATS", statsA)
	}

	if !util.SkipIPv6() {
		answersAAAA, statsAAAA, err = measurements.QueryDNSResolvers(name, "AAAA", resolver)
		if err != nil {
			util.Log(checkName, util.LevelError, "RESOLVER_ERROR_AAAA", err.Error())
			return false
		}
		util.Log(checkName, util.LevelDetail, "RESOLVER_STATS", statsAAAA)
	}

	if len(answersA)+len(answersAAAA) == 0 {
		util.Log(
			checkName,
			util.LevelError,
			"RESOLVER_ZERO_ANSWER",
			fmt.Sprintf("Resolver %s gave no answers to query %s", resolver, name),
		)
		return false
	}

	util.Log(
		checkName,
		util.LevelInfo,
		"RESOLVER_ANSWERS",
		fmt.Sprintf("Resolver %s's answer(s) to query %s is: %v + %v", resolver, name, answersA, answersAAAA),
	)

	// verify if answers are in predefined known CIDR ranges
	answers := append(answersA, answersAAAA...)
	for _, ip := range answers {
		util.CheckIPForProvider(checkName, ip, name)
	}

	return true
}
