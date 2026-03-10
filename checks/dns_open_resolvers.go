package checks

import (
	"fmt"
	"netiscope/log"
	"netiscope/util"
)

type DNSGoogleOpenResolverCheck struct {
	netiscopeCheckBase
}
type DNSCloudflareOpenResolverCheck struct {
	netiscopeCheckBase
}
type DNSQuad9OpenResolverCheck struct {
	netiscopeCheckBase
}

// CheckGoogleDNS checks Google's open resolver
func (check *DNSGoogleOpenResolverCheck) Start() {
	checkOpenResolver(
		&check.netiscopeCheckBase,
		"Google",
		"IPv4",
		[]string{"8.8.8.8", "8.8.4.4"},
	)
	checkOpenResolver(
		&check.netiscopeCheckBase,
		"Google",
		"IPv6",
		[]string{"2001:4860:4860::8888", "2001:4860:4860::8844"},
	)
	check.Log(log.LevelInfo, "FINISH", "Finished")
}

// CheckCloudflareDNS checks Cloudflare's open resolver
func (check *DNSCloudflareOpenResolverCheck) Start() {
	checkOpenResolver(
		&check.netiscopeCheckBase,
		"Cloudflare",
		"IPv4",
		[]string{"1.1.1.1", "1.0.0.1"},
	)
	checkOpenResolver(
		&check.netiscopeCheckBase,
		"Cloudflare",
		"IPv6",
		[]string{"2606:4700:4700::1111", "2606:4700:4700::1001"},
	)
	check.Log(log.LevelInfo, "FINISH", "Finished")
}

// CheckQuad9DNS checks Quad9's open resolver
func (check *DNSQuad9OpenResolverCheck) Start() {
	checkOpenResolver(
		&check.netiscopeCheckBase,
		"Quad9",
		"IPv4",
		[]string{"9.9.9.9", "149.112.112.112"},
	)
	checkOpenResolver(
		&check.netiscopeCheckBase,
		"Quad9",
		"IPv6",
		[]string{"2620:fe::fe", "2620:fe::9"},
	)
	check.Log(log.LevelInfo, "FINISH", "Finished")
}

func checkOpenResolver(
	check *netiscopeCheckBase,
	provider string,
	af string,
	resolvers []string,
) {
	if (af == "IPv4" && !util.SkipIPv4()) || (af == "IPv6" && !util.SkipIPv6()) {
		check.Log(
			log.LevelInfo,
			"CKECKING_OPEN_DNS_RESOLVER",
			fmt.Sprintf(
				"Checking %s's %s resolvers %v",
				provider, af, resolvers,
			),
		)
		testResolversOnAddressFamily(check, "OPEN_DNS_RESOLVER", af, "open DNS resolvers", resolvers)
	}
}
