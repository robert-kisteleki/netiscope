package checks

import (
	"fmt"
	"netiscope/log"
	"netiscope/util"
)

// CheckOpenDNSResolvers checks all (defined) open DNS resolvers
// it's basically a shorthand for doing checks against the predefined open resolvers
func CheckOpenDNSResolvers(check log.Check) {
	defer close(check.Collector)
	checkGoogleDNS(check)
	checkCloudflareDNS(check)
	checkQuad9DNS(check)
}

// CheckGoogleDNS checks Google's open resolver
func CheckGoogleDNS(check log.Check) {
	defer close(check.Collector)
	checkGoogleDNS(check)
}
func checkGoogleDNS(check log.Check) {
	checkOpenResolver(
		check,
		"Google",
		"IPv4",
		[]string{"8.8.8.8", "8.8.4.4"},
	)
	checkOpenResolver(
		check,
		"Google",
		"IPv6",
		[]string{"2001:4860:4860::8888", "2001:4860:4860::8844"},
	)
}

// CheckCloudflareDNS checks Cloudflare's open resolver
func CheckCloudflareDNS(check log.Check) {
	defer close(check.Collector)
	checkCloudflareDNS(check)
}
func checkCloudflareDNS(check log.Check) {
	checkOpenResolver(
		check,
		"Cloudflare",
		"IPv4",
		[]string{"1.1.1.1", "1.0.0.1"},
	)
	checkOpenResolver(
		check,
		"Cloudflare",
		"IPv6",
		[]string{"2606:4700:4700::1111", "2606:4700:4700::1001"},
	)
}

// CheckQuad9DNS checks Quad9's open resolver
func CheckQuad9DNS(check log.Check) {
	defer close(check.Collector)
	checkQuad9DNS(check)
}
func checkQuad9DNS(check log.Check) {
	checkOpenResolver(
		check,
		"Quad9",
		"IPv4",
		[]string{"9.9.9.9"},
	)
	checkOpenResolver(
		check,
		"Quad9",
		"IPv6",
		[]string{"2620:fe::fe", "2620:fe::9", "2620:fe::10", "2620:fe::fe:10", "2620:fe::11", "2620:fe::fe:11"},
	)
}

func checkOpenResolver(
	check log.Check,
	provider string,
	af string,
	resolvers []string,
) {
	if (af == "IPv4" && !util.SkipIPv4()) || (af == "IPv6" && !util.SkipIPv6()) {
		log.NewResultItem(
			check, log.LevelInfo, "CKECKING_OPEN_DNS_RESOLVER",
			fmt.Sprintf(
				"Checking %s's %s resolvers %v",
				provider, af, resolvers,
			),
		)
		testResolversOnAddressFamily(check, "OPEN_DNS_RESOLVER", af, "open DNS resolvers", resolvers)
	}
}
