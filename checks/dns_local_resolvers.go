package checks

import (
	"bufio"
	"fmt"
	"netiscope/util"
	"os"
	"strings"
	"time"
)

// resolv.conf parse results
var (
	rcDomain      string
	rcResolversV4 []string
	rcResolversV6 []string
	rcSearch      []string
)

// CheckDNSResolvers ...
func CheckDNSResolvers() {

	if !loadResolvers() {
		util.Log(checkName, util.LevelError, "NO_RESOLV_CONF", "Could not load DNS resolver data from resolv.conf")
		return
	}

	testLocalResolvers()
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

func testLocalResolvers() {
	var pingV4, pingV6 multipleResult
	var queryV4, queryV6 multipleResult

	if len(rcResolversV4) == 0 && len(rcResolversV6) == 0 {
		util.Log(checkName, util.LevelError, "NO_RESOLVERS", "No resolvers defined in resolv.conf")
		return
	}

	// ping them
	if util.GetConfigBoolParam("dns_resolvers", "ping", false) {

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
	if util.GetConfigBoolParam("dns_resolvers", "query", false) {
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
