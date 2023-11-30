package checks

import (
	"bufio"
	"fmt"
	"netiscope/log"
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

// CheckLocalDNSResolvers reads the local DNS reolver configuration and tests the servers listed therein
func CheckLocalDNSResolvers(check log.Check) {
	defer close(check.Collector)
	if !loadResolvers(check) {
		log.NewResultItem(
			check, log.LevelError, "NO_RESOLV_CONF",
			"Could not load DNS resolver data from resolv.conf",
		)
		return
	}
	testLocalResolvers(check)
}

// read and collect useful entries from resolv.conf
// return: success or not
func loadResolvers(check log.Check) bool {
	resolvconf, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return false
	}

	rcstat, err := resolvconf.Stat()
	if err != nil {
		return false
	}
	log.Track(check)
	log.NewResultItem(
		check, log.LevelInfo, "RESOLVCONF_DATE",
		fmt.Sprintf("resolv.conf was last modified %s ago (at %s)",
			log.DurationToHuman(time.Since(rcstat.ModTime())),
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

	log.NewResultItem(check, log.LevelInfo, "DOMAIN", fmt.Sprintf("Current domain is: %s", rcDomain))
	if !util.SkipIPv4() {
		log.NewResultItem(check, log.LevelInfo, "LOCAL_DNS_RESOLVERS", fmt.Sprintf("IPv4 resolvers: %s", rcResolversV4))
	}
	if !util.SkipIPv6() {
		log.NewResultItem(check, log.LevelInfo, "LOCAL_DNS_RESOLVERS", fmt.Sprintf("IPv6 resolvers: %s", rcResolversV6))
	}
	log.NewResultItem(check, log.LevelInfo, "SEARCH", fmt.Sprintf("Search path: %s", rcSearch))
	log.Track(check)

	return true
}

// test the set of local resolvers on IPv4 and IPv6
func testLocalResolvers(check log.Check) {
	if !util.SkipIPv4() {
		if len(rcResolversV4) > 0 {
			testResolversOnAddressFamily(check, "LOCAL_DNS_RESOLVER", "IPv4", "local DNS resolvers", rcResolversV4)
		} else {
			log.NewResultItem(check, log.LevelWarning, "NO_LOCAL_IPV4_RESOLVERS", "No IPv4 resolvers defined in resolv.conf")
			log.Track(check)
		}
	}

	if !util.SkipIPv6() {
		if len(rcResolversV6) > 0 {
			testResolversOnAddressFamily(check, "LOCAL_DNS_RESOLVER", "IPv6", "local DNS resolvers", rcResolversV6)
		} else {
			log.NewResultItem(check, log.LevelWarning, "NO_LOCAL_IPV6_RESOLVERS", "No IPv6 resolvers defined in resolv.conf")
			log.Track(check)
		}
	}

	if len(rcResolversV4) == 0 && len(rcResolversV6) == 0 {
		log.NewResultItem(check, log.LevelError, "NO_LOCAL_RESOLVERS", "No DNS resolvers defined in resolv.conf")
	}
}
