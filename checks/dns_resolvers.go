package checks

import (
	"fmt"
	"strings"

	"netiscope/measurements"
	"netiscope/util"
)

type multipleResult [3]int

const (
	resultSuccess = 0
	resultPartial = 1
	resultFailure = 2
)

// ping resolvers
// return tuple of [#success, #partial, #fail]
func pingResolvers(rtype string, resolvers []string) (results multipleResult) {
	for _, resolver := range resolvers {
		util.Log(
			checkName,
			util.LevelInfo,
			fmt.Sprintf("PING_%s_RESOLVER", strings.ToUpper(rtype)),
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
				fmt.Sprintf("Resolver %s shows packet loss", resolver),
			)
		}
	}

	return
}

// query some names from the resolvers
// return tuple of [#success, #partial, #fail]
func queryResolvers(rtype string, resolvers []string) (results multipleResult) {
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
				fmt.Sprintf("%s_RESOLVER_FAILS", strings.ToUpper(rtype)),
				fmt.Sprintf("Resolver %s is not answering queries", resolver),
			)
		case nsuccess > 0 && nfail > 0:
			results[resultPartial]++
			util.Log(
				checkName,
				util.LevelWarning,
				fmt.Sprintf("%s_RESOLVER_FLAKY", strings.ToUpper(rtype)),
				fmt.Sprintf("Resolver %s failed to answer some queries", resolver),
			)
		case nsuccess > 0 && nfail == 0:
			results[resultSuccess]++
			util.Log(
				checkName,
				util.LevelInfo,
				fmt.Sprintf("%s_RESOLVER_WORKS", strings.ToUpper(rtype)),
				fmt.Sprintf("Resolver %s answered all queries", resolver),
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

	answers := append(answersA, answersAAAA...)

	util.Log(
		checkName,
		util.LevelInfo,
		"RESOLVER_ANSWERS",
		fmt.Sprintf("Resolver %s's answer(s) to query %s is: %v", resolver, name, answers),
	)

	// verify if answers are in predefined known CIDR ranges
	for _, ip := range answers {
		util.CheckIPForProvider(checkName, ip, name)
	}

	return true
}

func testResolversOnAddressFamily(rtype string, af string, resolvers []string) {
	if shouldCheckDNSFunction("ping") {
		reportResolversOnAddressFamily(rtype, af, "PING", "reachable", resolvers, pingResolvers(rtype, resolvers))
	}
	if shouldCheckDNSFunction("query") {
		reportResolversOnAddressFamily(rtype, af, "QUERY", "answering", resolvers, queryResolvers(rtype, resolvers))
	}
}

func reportResolversOnAddressFamily(rtype string, af string, test string, verb string, resolvers []string, results multipleResult) {
	switch {
	case len(resolvers) == results[resultSuccess]:
		util.Log(checkName, util.LevelInfo,
			fmt.Sprintf("%s_RESOLVER_%s_OK", strings.ToUpper(rtype), test),
			fmt.Sprintf("%s %s DNS resolvers %v are %s", strings.Title(rtype), af, resolvers, verb),
		)
	case results[resultPartial] > 0:
		util.Log(checkName, util.LevelWarning,
			fmt.Sprintf("%s_RESOLVER_%s_PARTIAL", strings.ToUpper(rtype), test),
			fmt.Sprintf("%s %s DNS resolvers %v are only partially %s", strings.Title(rtype), af, resolvers, verb),
		)
	default:
		util.Log(checkName, util.LevelError,
			fmt.Sprintf("%s_RESOLVER_%s_FAIL", strings.ToUpper(rtype), test),
			fmt.Sprintf("%s %s DNS resolvers %v are not %s", strings.Title(rtype), af, resolvers, verb),
		)
	}
}

func shouldCheckDNSFunction(function string) bool {
	return util.GetConfigBoolParam("dns_resolvers", function, false)
}
