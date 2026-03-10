package checks

import (
	"bufio"
	"fmt"
	"netiscope/util"
	"os"
	"strings"
	"time"
)

// CheckLocalDNSResolvers reads the local DNS resolver configuration and tests the servers listed therein
type DNSLocalResolversCheck struct {
	netiscopeCheckBase
	rcDomain      string
	rcResolversV4 []string
	rcResolversV6 []string
	rcSearch      []string
}

// Start executes the local DNS resolver check
func (check *DNSLocalResolversCheck) start() {
	check.netiscopeCheckBase.start()

	if !check.loadResolvers() {
		check.log(LogLevelError, "NO_RESOLV_CONF", "Could not load DNS resolver data from resolv.conf")
		return
	}
	check.testLocalResolvers()

	check.netiscopeCheckBase.finish()
}

// read and collect useful entries from resolv.conf
// return: success or not
func (check *DNSLocalResolversCheck) loadResolvers() bool {
	resolvconf, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return false
	}

	rcstat, err := resolvconf.Stat()
	if err != nil {
		return false
	}
	check.log(
		LogLevelInfo,
		"RESOLVCONF_DATE",
		fmt.Sprintf("resolv.conf was last modified %s ago (at %s)",
			DurationToHuman(time.Since(rcstat.ModTime())),
			rcstat.ModTime().Format(time.RFC3339),
		),
	)

	scanner := bufio.NewScanner(resolvconf)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "domain") {
			check.rcDomain = strings.Fields(line)[1]
		} else if strings.HasPrefix(line, "nameserver") {
			resolver := strings.Fields(line)[1]
			if util.IsIPv6(resolver) {
				check.rcResolversV6 = append(check.rcResolversV6, resolver)
			} else {
				check.rcResolversV4 = append(check.rcResolversV4, resolver)
			}
		} else if strings.HasPrefix(line, "search") {
			check.rcSearch = append(check.rcSearch, strings.Fields(line)[1])
		}
	}

	check.log(LogLevelInfo, "DOMAIN", fmt.Sprintf("Current domain is: %s", check.rcDomain))
	if !util.SkipIPv4() {
		check.log(LogLevelInfo, "LOCAL_DNS_RESOLVERS", fmt.Sprintf("IPv4 resolvers: %s", check.rcResolversV4))
	}
	if !util.SkipIPv6() {
		check.log(LogLevelInfo, "LOCAL_DNS_RESOLVERS", fmt.Sprintf("IPv6 resolvers: %s", check.rcResolversV6))
	}
	check.log(LogLevelInfo, "SEARCH", fmt.Sprintf("Search path: %s", check.rcSearch))

	return true
}

// test the set of local resolvers on IPv4 and IPv6
func (check *DNSLocalResolversCheck) testLocalResolvers() {
	if !util.SkipIPv4() {
		if len(check.rcResolversV4) > 0 {
			testResolversOnAddressFamily(&check.netiscopeCheckBase, "LOCAL_DNS_RESOLVER", "IPv4", "local DNS resolvers", check.rcResolversV4)
		} else {
			check.log(LogLevelWarning, "NO_LOCAL_IPV4_RESOLVERS", "No IPv4 resolvers defined in resolv.conf")
		}
	}

	if !util.SkipIPv6() {
		if len(check.rcResolversV6) > 0 {
			testResolversOnAddressFamily(&check.netiscopeCheckBase, "LOCAL_DNS_RESOLVER", "IPv6", "local DNS resolvers", check.rcResolversV6)
		} else {
			check.log(LogLevelWarning, "NO_LOCAL_IPV6_RESOLVERS", "No IPv6 resolvers defined in resolv.conf")
		}
	}

	if len(check.rcResolversV4) == 0 && len(check.rcResolversV6) == 0 {
		check.log(LogLevelError, "NO_LOCAL_RESOLVERS", "No DNS resolvers defined in resolv.conf")
	}
}
