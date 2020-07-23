package checks

import (
	"fmt"
	"netiscope/util"
)

// CheckOpenResolvers checks all (defined) open DNS resolvers
// it's basically a shorthand for doing checks against the predefined open resolvers
func CheckOpenResolvers() {
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

func checkOpenResolver(
	provider string,
	af string,
	addresses []string) {

	var results multipleResult

	// ping them
	if util.GetConfigBoolParam("dns_resolvers", "ping", false) {

		if (af == "IPv4" && !util.SkipIPv4()) || (af == "IPv6" && !util.SkipIPv6()) {
			results = pingResolvers(addresses)
			if results[resultFailure] > 0 {
				util.Log(
					checkName,
					util.LevelWarning,
					"ALL_PING_FAIL",
					fmt.Sprintf(
						"%s resolvers for %s are unreachable",
						af, provider,
					),
				)
			}
		}
	}

	// query them
	if util.GetConfigBoolParam("dns_resolvers", "query", false) {
		if (af == "IPv4" && !util.SkipIPv4()) || (af == "IPv6" && !util.SkipIPv6()) {
			results = queryResolvers(addresses)

			if results[resultFailure] > 0 {
				util.Log(
					checkName,
					util.LevelWarning,
					"SOME_QUERY_FAIL",
					fmt.Sprintf(
						"%s resolvers for %s are not always answering queries",
						af, provider,
					),
				)
			}
			if results[resultSuccess] == 0 {
				util.Log(
					checkName,
					util.LevelError,
					"ALL_QUERY_FAIL",
					fmt.Sprintf(
						"%s resolvers for %s are not answering queries",
						af, provider,
					),
				)
			}
		}
	}
}
