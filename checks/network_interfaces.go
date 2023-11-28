package checks

import (
	"fmt"
	"net"

	"netiscope/log"
	"netiscope/util"
)

// CheckNetworkInterfaces evaulates the available network interfaces
func CheckNetworkInterfaces(check log.Check) {
	defer close(check.Collector)

	ifaces, err := net.Interfaces()
	if err != nil {
		// it's probably very bad if we got an error
		log.NewResultItem(check, log.LevelFatal, "NO_INTERFACES", "Error evaluating network interfaces")
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
				IPv6Unicast = IPv6Unicast || evaluateIPv6NetworkAddress(check, iface.Name, addr)
			} else if !util.SkipIPv4() && util.IsIPv4(ipstring) {
				IPv4Unicast = IPv4Unicast || evaluateIPv4NetworkAddress(check, iface.Name, addr)
			}
		}
	}

	// any useful IPv4 addresses found?
	if !util.SkipIPv4() && !IPv4Unicast {
		log.NewResultItem(check, log.LevelWarning, "NO_IPV4", "No routable IPv4 addresses found, disabling IPv4 checks")
		util.SetFailedIPv4()
	}

	// any useful addresses IPv6 found?
	if !util.SkipIPv6() && !IPv6Unicast {
		log.NewResultItem(check, log.LevelWarning, "NO_IPV6", "No routable IPv6 addresses found, disabling IPv6 checks")
		util.SetFailedIPv6()
	}

	// any useful addresses found at all?
	if !IPv4Unicast && !IPv6Unicast {
		log.NewResultItem(check, log.LevelError, "NO_ROUTABLE", "No routable addresses found")
	}

	// TODO: check if the gateway(s) is/are reachable?
}

// evaluateAddr checks if a given address seems to be useful
func evaluateIPv4NetworkAddress(
	check log.Check,
	ifname string,
	addr net.Addr,
) bool {
	ip, _, _ := net.ParseCIDR(addr.String())
	ipstring := ip.String()

	// IPv4 routable?
	if !util.SkipIPv4() && ip.IsGlobalUnicast() {
		if util.IsIPv4NAT(ipstring) {
			log.NewResultItem(
				check,
				log.LevelInfo,
				"IPV4",
				fmt.Sprintf("Local address %s (NAT, RFC1918)", ipstring),
			)
		} else if util.IsIPv4Suspicious(ipstring) {
			log.NewResultItem(
				check,
				log.LevelWarning,
				"IPV4",
				fmt.Sprintf("Local address %s (suspicious)", ipstring),
			)
		} else {
			log.NewResultItem(
				check,
				log.LevelInfo,
				"IPV4",
				fmt.Sprintf("Local address %s", ipstring),
			)
		}
		return true
	}

	// IPv4 non-routable?
	if !util.SkipIPv4() && ip.IsLinkLocalUnicast() {
		if util.IsIPv4DCHP(ipstring) {
			log.NewResultItem(
				check,
				log.LevelWarning,
				"IPV4",
				fmt.Sprintf("Local address %s (no address obtained via DHCP?)", ipstring),
			)
			return false
		}
	}

	return false
}

func evaluateIPv6NetworkAddress(
	check log.Check,
	ifname string,
	addr net.Addr,
) bool {
	ip, _, _ := net.ParseCIDR(addr.String())
	ipstring := ip.String()

	// IPv6 routable?
	if !util.SkipIPv6() && ip.IsGlobalUnicast() && !util.IsIPv6ULA(ipstring) {
		log.NewResultItem(
			check, log.LevelInfo, "IPV6",
			fmt.Sprintf("Local address %s", ipstring),
		)
		return true
	}

	return false
}
