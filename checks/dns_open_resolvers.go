package checks

import (
	ping "netiscope/measurements"
	"netiscope/util"
)

// CheckOpenResolvers checks all (defined) open DNS resolvers
// it's basically a shorthand for doing checks against the predefined open resolvers
func CheckOpenResolvers() {
	CheckGoogleDNS()
	CheckCloudflareDNS()
	CheckQuad9DNS()
}

// CheckGoogleDNS check Google's opns DNS resolver
func CheckGoogleDNS() {
	if !util.SkipIPv4() {
		checkOpenResolver("8.8.8.8")
		checkOpenResolver("8.8.4.4")
	}
	if !util.SkipIPv6() {
		checkOpenResolver("2001:4860:4860::8888")
		checkOpenResolver("2001:4860:4860::8844")
	}
}

// CheckCloudflareDNS check Cloudflare's 1.1.1.1 (IPv4) resolver
func CheckCloudflareDNS() {
	if !util.SkipIPv4() {
		checkOpenResolver("1.1.1.1")
		checkOpenResolver("1.0.0.1")
	}
	if !util.SkipIPv6() {
		checkOpenResolver("2606:4700:4700::1111")
		checkOpenResolver("2606:4700:4700::1001")
	}
}

// CheckQuad9DNS check Quad9's 9.9.9.9 (IPv4) resolver
func CheckQuad9DNS() {
	if !util.SkipIPv4() {
		checkOpenResolver("9.9.9.9")
	}
	if !util.SkipIPv6() {
		checkOpenResolver("2620:fe::fe")
		checkOpenResolver("2620:fe::9")
		checkOpenResolver("2620:fe::10")
		checkOpenResolver("2620:fe::fe:10")
		checkOpenResolver("2620:fe::11")
		checkOpenResolver("2620:fe::fe:11")
	}
}

func checkOpenResolver(resolver string) {
	_ = ping.Ping(checkName, resolver)

	// TODO: DNS53, DoT, DoH
}
