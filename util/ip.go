package util

import (
	"fmt"
	"math/big"
	"net"
	"netiscope/log"
	"strings"
)

var (
	// well-known IPv4 CIDR blocks
	cidrIPv4NAT = []net.IPNet{
		makeIPNet("10.0.0.0/8"),
		makeIPNet("172.16.0.0/12"),
		makeIPNet("192.168.0.0/16"),
	}
	cidrIPv4DHCP       = []net.IPNet{makeIPNet("169.254.0.0/16")}
	cidrIPv4Suspicious = []net.IPNet{
		makeIPNet("1.0.0.0/24"),
		makeIPNet("1.2.3.0/24"),
	}

	// well-known IPv6 CIDR blocks
	cidrIPv6ULA   = []net.IPNet{makeIPNet("fc00::/7")}
	cidrIPv6NAT64 = []net.IPNet{makeIPNet("64:ff9b::/96")}
)

// CIDR ranges for predefined providers. Contents are loaded fro the config file
var cidrProviders = make(map[string][]net.IPNet)

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

// IsIPv6NAT64 determines if an IP address is IPv6 NAT64 (RFC 6052)
func IsIPv6NAT64(ip string) bool {
	return IsInCIDRList(ip, cidrIPv6NAT64)
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
	if IsIPv6NAT64(ip) {
		// NAT64, unwrap the IPv4 address
		b := big.NewInt(0).SetBytes(net.ParseIP(ip)).Bytes()
		ip = net.IPv4(b[11], b[12], b[13], b[14]).String()
	}
	return true, IsInCIDRList(ip, cidrs)
}

// CheckIPForProvider makes log entries about an IP being in a provider's CIDR list
func CheckIPForProvider(
	check *log.Check,
	ip string,
	provider string,
) {
	known, contains := isIPInProviderCIDRBlock(ip, provider)
	switch {
	case !known:
		log.NewResultItem(
			check, log.LevelInfo, "PROVIDER_CIDR_UNKNOWN",
			fmt.Sprintf("CIDR block list is unknown for %s (IP: %v)", provider, ip),
		)
	case known && contains:
		log.NewResultItem(
			check, log.LevelInfo, "PROVIDER_CIDR_OK",
			fmt.Sprintf("The IP %s is in the CIDR block list for %s", ip, provider),
		)
	case known && !contains:
		log.NewResultItem(
			check, log.LevelWarning, "PROVIDER_CIDR_NOT_OK",
			fmt.Sprintf("The IP %s is not in the CIDR block list for %s", ip, provider),
		)
	}
}
