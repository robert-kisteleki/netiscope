package util

import (
	"fmt"
	"net"
	"strings"
)

// well-known CIDR blocks
var (
	cidrIPv4NAT        []net.IPNet = make([]net.IPNet, 0) // RFC 1918
	cidrIPv4DHCP       []net.IPNet = make([]net.IPNet, 0) // RFC 3927
	cidrIPv4Suspicious []net.IPNet = make([]net.IPNet, 0) // 1.1.1.1 and the like
	cidrIPv6ULA        []net.IPNet = make([]net.IPNet, 0) // RFC 4193
)

// CIDR ranges for predefined providers. Contents are loaded fro the config file
var cidrProviders = make(map[string][]net.IPNet)

func init() {
	// IPv4
	cidrIPv4NAT = append(cidrIPv4NAT,
		makeIPNet("10.0.0.0/8"),
		makeIPNet("172.16.0.0/12"),
		makeIPNet("192.168.0.0/16"),
	)
	cidrIPv4DHCP = append(cidrIPv4DHCP,
		makeIPNet("169.254.0.0/16"),
	)
	cidrIPv4Suspicious = append(cidrIPv4Suspicious,
		makeIPNet("1.0.0.0/24"),
		makeIPNet("1.2.3.0/24"),
	)

	// IPv6
	cidrIPv6ULA = append(cidrIPv6ULA,
		makeIPNet("fc00::/7"),
	)
}

func makeIPNet(cidr string) net.IPNet {
	_, ipnet, _ := net.ParseCIDR(cidr)
	return *ipnet
}

// IsAF determines if an IP address has the particular address family
func IsAF(af int, ip string) bool {
	return (af == 4 && IsIPv4(ip)) || (af == 6 && IsIPv6(ip))
}

// IsIPv6 determines if an IP address is IPv6
func IsIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}

// IsIPv4 determines if an IP address is IPv4
func IsIPv4(ip string) bool {
	return !IsIPv6(ip)
}

// IsInCIDRList determines if an addess is in any of the CIDR prefixes given
func IsInCIDRList(address string, cidrlist []net.IPNet) bool {
	ip := net.ParseIP(address)
	for _, cidr := range cidrlist {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// IsIPv6ULA determines if an IP address is IPv6 ULA (RFC 4193)
func IsIPv6ULA(ip string) bool {
	return IsInCIDRList(ip, cidrIPv6ULA)
}

// IsIPv4NAT determines if an IPv4 address is private (RFC 1918)
func IsIPv4NAT(ip string) bool {
	return IsInCIDRList(ip, cidrIPv4NAT)
}

// IsIPv4Suspicious determines if an IPv4 address is weird as an end user IP
func IsIPv4Suspicious(ip string) bool {
	return IsInCIDRList(ip, cidrIPv4Suspicious)
}

// IsIPv4DCHP determines if an IPv4 address is link local (DHCP failed? RFC 3927)
func IsIPv4DCHP(ip string) bool {
	return IsInCIDRList(ip, cidrIPv4DHCP)
}

// IsIPInProviderCIDRBlock checks if a provider's CIDR blocks contain a particular IP
// @return
// is-provider-cidr-list-known?
// is-ip-in-provider-cidr-list?
func isIPInProviderCIDRBlock(ip string, provider string) (bool, bool) {
	cidrs, ok := cidrProviders[provider]
	if !ok {
		return false, false
	}
	return true, IsInCIDRList(ip, cidrs)
}

// CheckIPForProvider makes log entries about an IP being in a provider's CIDR list
func CheckIPForProvider(checkName string, ip string, provider string) {
	known, contains := isIPInProviderCIDRBlock(ip, provider)
	switch {
	case !known:
		Log(
			checkName,
			LevelDetail,
			"PROVIDER_CIDR_UNKNOWN",
			fmt.Sprintf("CIDR block list is unknown for %s", provider),
		)
	case known && contains:
		Log(
			checkName,
			LevelInfo,
			"PROVIDER_CIDR_OK",
			fmt.Sprintf("The IP %s is in the CIDR block list for %s", ip, provider),
		)
	case known && !contains:
		Log(
			checkName,
			LevelError,
			"PROVIDER_CIDR_NOT_OK",
			fmt.Sprintf("The IP %s is not in the CIDR block list for %s", ip, provider),
		)
	}
}
