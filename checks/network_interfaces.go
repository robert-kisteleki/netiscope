package checks

import (
	"net"

	"netiscope/util"
)

// CheckNetworkInterfaces evaulates the available network interfaces
func CheckNetworkInterfaces() {

	ifaces, err := net.Interfaces()
	if err != nil {
		// it's probably very bad if we got an error
		util.Log(checkName, util.LevelFatal, "NO_INTERFACES", "Error evaluating network interfaces")
		return
	}

	// were there any useful v4/v6 addresses?
	var IPv4Unicast, IPv6Unicast bool

	// now check all network interfaces and look for useful IP addresses
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			ipstring := ip.String()

			if !util.SkipIPv6() && util.IsIPv6(ipstring) {
				IPv6Unicast = IPv6Unicast || evaluateIPv6NetworkAddress(iface.Name, addr)
			} else if !util.SkipIPv4() && util.IsIPv4(ipstring) {
				IPv4Unicast = IPv4Unicast || evaluateIPv4NetworkAddress(iface.Name, addr)
			}
		}
	}

	// any useful IPv4 addresses found?
	if !util.SkipIPv4() && !IPv4Unicast {
		util.Log(checkName, util.LevelWarning, "NO_IPV4", "No routable IPv4 addresses found")
	}

	// any useful addresses IPv6 found?
	if !util.SkipIPv6() && !IPv6Unicast {
		util.Log(checkName, util.LevelWarning, "NO_IPV6", "No routable IPv6 addresses found")
	}

	// any useful addresses found at all?
	if !IPv4Unicast && !IPv6Unicast {
		util.Log(checkName, util.LevelError, "NO_ROUTABLE", "No routable addresses found")
	}

	// TODO: check if the gateway(s) is/are reachable?
}

// evaluateAddr checks if a given address seems to be useful
func evaluateIPv4NetworkAddress(ifname string, addr net.Addr) bool {
	ip, _, _ := net.ParseCIDR(addr.String())
	ipstring := ip.String()

	// IPv4 routable?
	if !util.SkipIPv4() && ip.IsGlobalUnicast() {
		if util.IsIPv4NAT(ipstring) {
			util.Log(
				checkName,
				util.LevelInfo,
				"IPV4",
				map[string]string{ifname: "Local address " + ipstring + " (NAT, RFC1918)"},
			)
		} else if util.IsIPv4Suspicious(ipstring) {
			util.Log(
				checkName,
				util.LevelWarning,
				"IPV4",
				map[string]string{ifname: "Local address " + ipstring + " (suspicious)"},
			)
		} else {
			util.Log(
				checkName,
				util.LevelInfo,
				"IPV4",
				map[string]string{ifname: "Local address " + ipstring},
			)
		}
		return true
	}

	// IPv4 non-routable?
	if !util.SkipIPv4() && ip.IsLinkLocalUnicast() {
		if util.IsIPv4DCHP(ipstring) {
			util.Log(
				checkName,
				util.LevelWarning,
				"IPV4",
				map[string]string{ifname: "Local address " + ipstring + " (no address obtained via DHCP?)"},
			)
			return false
		}
	}

	return false
}

func evaluateIPv6NetworkAddress(ifname string, addr net.Addr) bool {
	ip, _, _ := net.ParseCIDR(addr.String())
	ipstring := ip.String()

	// IPv6 routable?
	if !util.SkipIPv6() && ip.IsGlobalUnicast() && !util.IsIPv6ULA(ipstring) {
		util.Log(
			checkName,
			util.LevelInfo,
			"IPV6",
			map[string]string{ifname: "Local address " + ipstring},
		)
		return true
	}

	return false
}
