package checks

import (
	"fmt"
	"strings"

	"netiscope/measurements"
	"netiscope/util"
)

// query the predefined list of names from a set of resolvers
// return a MultipleResult
func queryNamesFromResolvers(rtype string, resolvers []string) (results measurements.MultipleResult) {

	// the names to look up are in the config file
	names := util.GetDNSNamesToLookup()
	if len(names) == 0 {
		util.Log(
			checkName,
			util.LevelFatal,
			fmt.Sprintf("%s_NO_NAMES", strings.ToUpper(rtype)),
			"The list of names to look up is empty",
		)
		return
	}

	for _, resolver := range resolvers {

		// collect the results of looking up all names with this resolver
		var resolverResults measurements.MultipleResult
		for _, name := range names {
			resolverResults[queryNameFromResolver(name, resolver)]++
		}

		// now evaluate this resolver by looking at the the collected results
		// also update the ultimate returned result
		switch {
		case resolverResults[measurements.ResultSuccess] == 0 && resolverResults[measurements.ResultFailure] > 0:
			results[measurements.ResultFailure]++
			util.Log(
				checkName,
				util.LevelError,
				fmt.Sprintf("QUERY_%s_FAILS", strings.ToUpper(rtype)),
				fmt.Sprintf("Resolver %s is not answering queries", resolver),
			)
		case resolverResults[measurements.ResultSuccess] > 0 && resolverResults[measurements.ResultFailure] > 0:
			results[measurements.ResultPartial]++
			util.Log(
				checkName,
				util.LevelWarning,
				fmt.Sprintf("QUERY_%s_FLAKY", strings.ToUpper(rtype)),
				fmt.Sprintf("Resolver %s failed to answer some queries", resolver),
			)
		case resolverResults[measurements.ResultSuccess] > 0 && resolverResults[measurements.ResultFailure] == 0:
			results[measurements.ResultSuccess]++
			util.Log(
				checkName,
				util.LevelInfo,
				fmt.Sprintf("QUERY_%s_WORKS", strings.ToUpper(rtype)),
				fmt.Sprintf("Resolver %s answered all queries", resolver),
			)
		}
	}
	return
}

// ask one resolver for one query
// return ResultCode to indicate if it was successful
func queryNameFromResolver(name string, resolver string) measurements.ResultCode {
	var answersA, answersAAAA map[string][]string
	var err error

	if !util.SkipIPv4() {
		answersA, err = measurements.DNSQuery(checkName, name, "A", resolver, false, true)
		if err != nil {
			util.Log(checkName, util.LevelError, "RESOLVER_ERROR_A", err.Error())
			return measurements.ResultFailure
		}
	}

	if !util.SkipIPv6() {
		answersAAAA, err = measurements.DNSQuery(checkName, name, "AAAA", resolver, false, true)
		if err != nil {
			util.Log(checkName, util.LevelError, "RESOLVER_ERROR_AAAA", err.Error())
			return measurements.ResultFailure
		}
	}

	if len(answersA)+len(answersAAAA) == 0 {
		util.Log(
			checkName,
			util.LevelError,
			"RESOLVER_ZERO_ANSWER",
			fmt.Sprintf("Resolver %s gave no answers to query %s", resolver, name),
		)
		return measurements.ResultFailure
	}

	answers := append(answersA["A"], answersAAAA["AAAA"]...)

	util.Log(
		checkName,
		util.LevelInfo,
		"RESOLVER_ANSWERS",
		fmt.Sprintf("Resolver %s's answer(s) to query %s is: %v", resolver, name, answers),
	)

	// verify if answers are in predefined known CIDR ranges
	for _, ip := range answers {
		util.CheckIPForProvider(checkName, fmt.Sprint(ip), name)
	}

	return measurements.ResultSuccess
}

// test a set of resolvers on a particular address family
// mnemo: menmonic to use in log
// af: address family (IPv4 or IPv6)
// kind: which kind of resolver are we testing (local or open)
// resolvers: the resolvers to test
func testResolversOnAddressFamily(mnemo string, af string, kind string, resolvers []string) {
	if shouldCheckDNSFunction("ping") {
		reportResolversOnAddressFamily(
			mnemo, af, kind, "PING", "reachable", resolvers,
			measurements.PingServers(checkName, mnemo, resolvers),
		)
	}
	if shouldCheckDNSFunction("query") {
		reportResolversOnAddressFamily(
			mnemo, af, kind, "QUERY", "answering", resolvers,
			queryNamesFromResolvers(mnemo, resolvers),
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
	mnemo string,
	af string,
	kind string,
	test string,
	verb string,
	resolvers []string,
	results measurements.MultipleResult,
) {
	isare := "are"
	if len(resolvers) == 1 {
		isare = "is"
	}
	switch {
	case results[measurements.ResultPartial] == 0 && results[measurements.ResultFailure] == 0:
		util.Log(checkName, util.LevelInfo,
			fmt.Sprintf("%s_%s_OK", test, mnemo),
			fmt.Sprintf("%s %s %v %s %s properly", af, kind, resolvers, isare, verb),
		)
	case results[measurements.ResultPartial] > 0:
		util.Log(checkName, util.LevelWarning,
			fmt.Sprintf("%s_%s_PARTIAL", test, mnemo),
			fmt.Sprintf("%s %s %v %s only partially %s", af, kind, resolvers, isare, verb),
		)
	default:
		util.Log(checkName, util.LevelError,
			fmt.Sprintf("%s_%s_FAIL", test, mnemo),
			fmt.Sprintf("%s %s %v %s not %s properly", af, kind, resolvers, isare, verb),
		)
	}
}

// determine if, according to the configuration, this test should be done
func shouldCheckDNSFunction(function string) bool {
	return util.GetConfigBoolParam("dns", function, false)
}
