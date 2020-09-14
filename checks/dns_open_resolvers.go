package checks

import (
	"fmt"
	"netiscope/util"
)

// CheckOpenDNSResolvers checks all (defined) open DNS resolvers
// it's basically a shorthand for doing checks against the predefined open resolvers
func CheckOpenDNSResolvers() {
	CheckGoogleDNS()
	CheckCloudflareDNS()
	CheckQuad9DNS()
}

// CheckGoogleDNS checks Google's open resolver
func CheckGoogleDNS() {
	checkOpenResolver(
		"Google",
		"IPv4",
		[]string{"8.8.8.8", "8.8.4.4"},
	)
	checkOpenResolver(
		"Google",
		"IPv6",
		[]string{"2001:4860:4860::8888", "2001:4860:4860::8844"},
	)
}

// CheckCloudflareDNS checks Cloudflare's open resolver
func CheckCloudflareDNS() {
	checkOpenResolver(
		"Cloudflare",
		"IPv4",
		[]string{"1.1.1.1", "1.0.0.1"},
	)
	checkOpenResolver(
		"Cloudflare",
		"IPv6",
		[]string{"2606:4700:4700::1111", "2606:4700:4700::1001"},
	)
}

// CheckQuad9DNS checks Quad9's open resolver
func CheckQuad9DNS() {
	checkOpenResolver(
		"Quad9",
		"IPv4",
		[]string{"9.9.9.9"},
	)
	checkOpenResolver(
		"Quad9",
		"IPv6",
		[]string{"2620:fe::fe", "2620:fe::9", "2620:fe::10", "2620:fe::fe:10", "2620:fe::11", "2620:fe::fe:11"},
	)
}

func checkOpenResolver(provider string, af string, resolvers []string) {
	if (af == "IPv4" && !util.SkipIPv4()) || (af == "IPv6" && !util.SkipIPv6()) {
		util.Log(
			checkName,
			util.LevelInfo,
			"CKECKING_OPEN_DNS_RESOLVER",
			fmt.Sprintf(
				"Checking %s's %s resolvers %v",
				provider, af, resolvers,
			),
		)
		testResolversOnAddressFamily("OPEN_DNS_RESOLVER", af, "open DNS resolvers", resolvers)
	}
}
