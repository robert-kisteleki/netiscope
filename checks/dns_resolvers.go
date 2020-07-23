package checks

import (
	"fmt"

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
