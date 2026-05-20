package checks

import (
	"fmt"
	"github.com/robert-kisteleki/netiscope/util"
	"strings"
)

type DNSOpenResolverCheck struct {
	netiscopeCheckBase
}

// check an open resolver
func (check *DNSOpenResolverCheck) start() {
	check.netiscopeCheckBase.start()

	providers := util.GetOpenResolverList()
	for _, provider := range providers {
		parts := strings.Split(strings.ReplaceAll(provider, " ", ""), ",")
		if len(parts) < 2 {
			check.log(
				LogLevelError,
				"INVALID_OPEN_DNS_RESOLVER",
				fmt.Sprintf("Invalid open DNS resolver format for provider %s", provider),
			)
			continue
		}

		v4list := []string{}
		v6list := []string{}
		for _, part := range parts[1:] {
			if strings.Contains(part, ":") {
				v6list = append(v6list, part)
			} else {
				v4list = append(v4list, part)
			}
		}

		if len(v4list) > 0 {
			checkOpenResolver(&check.netiscopeCheckBase, parts[0], "IPv4", v4list)
		}
		if len(v6list) > 0 {
			checkOpenResolver(&check.netiscopeCheckBase, parts[0], "IPv6", v6list)
		}
		if len(v4list) == 0 && len(v6list) == 0 {
			check.log(
				LogLevelError,
				"INVALID_OPEN_DNS_RESOLVER",
				fmt.Sprintf("No IP addresses defined for open resolver %s", parts[0]),
			)
		}
	}
	check.netiscopeCheckBase.finish()
}

func checkOpenResolver(
	check *netiscopeCheckBase,
	provider string,
	af string,
	resolvers []string,
) {
	if (af == "IPv4" && !util.SkipIPv4()) || (af == "IPv6" && !util.SkipIPv6()) {
		check.log(
			LogLevelInfo,
			"CKECK_OPEN_DNS_RESOLVER_START",
			fmt.Sprintf(
				"Checking %s's %s resolvers %v",
				provider, af, resolvers,
			),
		)
		testResolversOnAddressFamily(check, "OPEN_DNS_RESOLVER", af, "open DNS resolvers", resolvers)
		check.log(
			LogLevelInfo,
			"CKECK_OPEN_DNS_RESOLVER_DONE",
			fmt.Sprintf(
				"Finished checking %s's %s resolvers",
				provider, af,
			),
		)
	}
}
