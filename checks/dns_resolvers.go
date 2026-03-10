package checks

import (
	"fmt"
	"strings"

	"netiscope/util"
)

// query the predefined list of names from a set of resolvers
// return a MultipleResult
func queryNamesFromResolvers(
	check *netiscopeCheckBase,
	rtype string,
	resolvers []string,
) (out MultipleResult) {

	// the names to look up are in the config file
	names := util.GetDNSNamesToLookup()
	if len(names) == 0 {
		check.log(
			LogLevelFatal,
			fmt.Sprintf("%s_NO_NAMES", strings.ToUpper(rtype)),
			"The list of names to look up is empty",
		)
		return
	}

	for _, resolver := range resolvers {
		// collect the results of looking up all names with this resolver
		var resolverResults MultipleResult
		for _, name := range names {
			if check.stopping {
				return
			}
			resolverResults[queryNameFromResolver(check, name, resolver)]++
		}

		// now evaluate this resolver by looking at the the collected results
		// also update the ultimate returned result
		switch {
		case resolverResults[ResultSuccess] == 0 && resolverResults[ResultFailure] > 0:
			out[ResultFailure]++
			check.log(
				LogLevelError,
				fmt.Sprintf("QUERY_%s_FAILS", strings.ToUpper(rtype)),
				fmt.Sprintf("Resolver %s is not answering queries", resolver),
			)
		case resolverResults[ResultSuccess] > 0 && resolverResults[ResultFailure] > 0:
			out[ResultPartial]++
			check.log(
				LogLevelWarning,
				fmt.Sprintf("QUERY_%s_FLAKY", strings.ToUpper(rtype)),
				fmt.Sprintf("Resolver %s failed to answer some queries", resolver),
			)
		case resolverResults[ResultSuccess] > 0 && resolverResults[ResultFailure] == 0:
			out[ResultSuccess]++
			check.log(
				LogLevelInfo,
				fmt.Sprintf("QUERY_%s_WORKS", strings.ToUpper(rtype)),
				fmt.Sprintf("Resolver %s answered all queries", resolver),
			)
		}
	}
	return
}

// ask one resolver for one query
// return ResultCode to indicate if it was successful
func queryNameFromResolver(
	check *netiscopeCheckBase,
	name string,
	resolver string,
) ResultCode {
	var answersA, answersAAAA map[string][]string
	var err error

	if !util.SkipIPv4() {
		answersA, err = DNSQuery(check, name, "A", resolver, false, true, true, false)
		if err != nil {
			check.log(LogLevelError, "RESOLVER_ERROR_A", err.Error())
			return ResultFailure
		}
	}

	if !util.SkipIPv6() {
		answersAAAA, err = DNSQuery(check, name, "AAAA", resolver, false, true, true, false)
		if err != nil {
			check.log(LogLevelError, "RESOLVER_ERROR_AAAA", err.Error())
			return ResultFailure
		}
	}

	if len(answersA)+len(answersAAAA) == 0 {
		check.log(
			LogLevelError,
			"RESOLVER_ZERO_ANSWER",
			fmt.Sprintf("Resolver %s gave no answers to query %s", resolver, name),
		)
		return ResultFailure
	}

	answers := append(answersA["A"], answersAAAA["AAAA"]...)

	check.log(
		LogLevelInfo,
		"RESOLVER_ANSWERS",
		fmt.Sprintf("Resolver %s's answer(s) to query %s is: %v", resolver, name, answers),
	)

	// verify if answers are in predefined known CIDR ranges
	for _, ip := range answers {
		CheckIPForProvider(check, fmt.Sprint(ip), name)
	}

	return ResultSuccess
}

// test a set of resolvers on a particular address family
// mnemo: menmonic to use in log
// af: address family (IPv4 or IPv6)
// kind: which kind of resolver are we testing (local or open)
// resolvers: the resolvers to test
func testResolversOnAddressFamily(
	check *netiscopeCheckBase,
	mnemo string,
	af string,
	kind string,
	resolvers []string,
) {
	if shouldCheckDNSFunction("ping") {
		reportResolversOnAddressFamily(
			check, mnemo, af, kind, "PING", "reachable", resolvers,
			PingServers(check, mnemo, resolvers),
		)
	}
	if shouldCheckDNSFunction("query") {
		reportResolversOnAddressFamily(
			check, mnemo, af, kind, "QUERY", "answering", resolvers,
			queryNamesFromResolvers(check, mnemo, resolvers),
		)
	}
}

// report on results for a set of resolvers on a particular address family
// mnemo: menmonic to use in log
// af: address family (IPv4 or IPv6)
// kind: which kind of resolver are we testing (local or open)
// test: which test (PING or QUERY)
// verb: an applicable verb for this test (reachable (PING) or answering (QUERY))
// resolvers: the resolvers to test
// results: the results to analyse
func reportResolversOnAddressFamily(
	check *netiscopeCheckBase,
	mnemo string,
	af string,
	kind string,
	test string,
	verb string,
	resolvers []string,
	out MultipleResult,
) {
	isare := "are"
	if len(resolvers) == 1 {
		isare = "is"
	}
	switch {
	case out[ResultPartial] == 0 && out[ResultFailure] == 0:
		check.log(
			LogLevelInfo,
			fmt.Sprintf("%s_%s_OK", test, mnemo),
			fmt.Sprintf("%s %s %v %s %s properly", af, kind, resolvers, isare, verb),
		)
	case out[ResultPartial] > 0:
		check.log(
			LogLevelWarning,
			fmt.Sprintf("%s_%s_PARTIAL", test, mnemo),
			fmt.Sprintf("%s %s %v %s only partially %s", af, kind, resolvers, isare, verb),
		)
	default:
		check.log(
			LogLevelError,
			fmt.Sprintf("%s_%s_FAIL", test, mnemo),
			fmt.Sprintf("%s %s %v %s not %s properly", af, kind, resolvers, isare, verb),
		)
	}
}

// determine if, according to the configuration, this test should be done
func shouldCheckDNSFunction(function string) bool {
	return util.GetConfigBoolParam("dns", function, false)
}
