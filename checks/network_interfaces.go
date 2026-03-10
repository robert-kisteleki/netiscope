package checks

import (
	"fmt"
	"net"

	"netiscope/util"
)

// CheckNetworkInterfaces evaulates the available network interfaces
type NetworkInterfacesCheck struct {
	netiscopeCheckBase
}

// Start executes the network interfaces check
func (check *NetworkInterfacesCheck) start() {
	check.netiscopeCheckBase.start()

	ifaces, err := net.Interfaces()
	if err != nil {
		// it's probably very bad if we got an error
		check.log(LogLevelFatal, "NO_INTERFACES", "Error evaluating network interfaces")
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
				IPv6Unicast = IPv6Unicast || check.evaluateIPv6NetworkAddress(iface.Name, addr)
			} else if !util.SkipIPv4() && util.IsIPv4(ipstring) {
				IPv4Unicast = IPv4Unicast || check.evaluateIPv4NetworkAddress(iface.Name, addr)
			}
		}
	}

	// any useful IPv4 addresses found?
	if !util.SkipIPv4() && !IPv4Unicast {
		check.log(LogLevelWarning, "NO_IPV4", "No routable IPv4 addresses found")
		util.SetFailedIPv4()
	}

	// any useful addresses IPv6 found?
	if !util.SkipIPv6() && !IPv6Unicast {
		check.log(LogLevelWarning, "NO_IPV6", "No routable IPv6 addresses found")
		util.SetFailedIPv6()
	}

	// any useful addresses found at all?
	if !IPv4Unicast && !IPv6Unicast {
		if util.SkipIPv4() && util.SkipIPv6() {
			check.log(
				LogLevelWarning,
				"NO_CHECK",
				"No checks to do (IPv4 and IPv6 checks are disabled)",
			)
		} else {
			check.log(
				LogLevelError,
				"NO_ROUTABLE_ADDRESSES_FOUND",
				"No routable addresses found",
			)
		}
	}

	// TODO: check if the gateway(s) is/are reachable?

	check.netiscopeCheckBase.finish()
}

// evaluateAddr checks if a given address seems to be useful
func (check *NetworkInterfacesCheck) evaluateIPv4NetworkAddress(
	ifname string,
	addr net.Addr,
) bool {
	ip, _, _ := net.ParseCIDR(addr.String())
	ipstring := ip.String()

	// IPv4 routable?
	if !util.SkipIPv4() && ip.IsGlobalUnicast() {
		if util.IsIPv4NAT(ipstring) {
			check.log(
				LogLevelInfo,
				"IPV4",
				fmt.Sprintf("Local address %s (NAT, RFC1918)", ipstring),
			)
		} else if util.IsIPv4Suspicious(ipstring) {
			check.log(
				LogLevelWarning,
				"IPV4",
				fmt.Sprintf("Local address %s (suspicious)", ipstring),
			)
		} else {
			check.log(
				LogLevelInfo,
				"IPV4",
				fmt.Sprintf("Local address %s", ipstring),
			)
		}
		return true
	}

	// IPv4 non-routable?
	if !util.SkipIPv4() && ip.IsLinkLocalUnicast() {
		if util.IsIPv4DCHP(ipstring) {
			check.log(
				LogLevelWarning,
				"IPV4",
				fmt.Sprintf("Local address %s (no address obtained via DHCP?)", ipstring),
			)
			return false
		}
	}

	return false
}

func (check *NetworkInterfacesCheck) evaluateIPv6NetworkAddress(
	ifname string,
	addr net.Addr,
) bool {
	ip, _, _ := net.ParseCIDR(addr.String())
	ipstring := ip.String()

	// IPv6 routable?
	if !util.SkipIPv6() && ip.IsGlobalUnicast() && !util.IsIPv6ULA(ipstring) {
		check.log(
			LogLevelInfo,
			"IPV6",
			fmt.Sprintf("Local address %s", ipstring),
		)
		return true
	}

	return false
}
