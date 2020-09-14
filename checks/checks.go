package checks

import (
	"netiscope/util"
)

var (
	// what checks are available
	knownChecks = map[string]checkFunction{
		"network_interfaces":  CheckNetworkInterfaces,
		"dns_local_resolvers": CheckLocalDNSResolvers,
		"dns_open_resolvers":  CheckOpenDNSResolvers,
		"1111":                CheckCloudflareDNS,
		"8888":                CheckGoogleDNS,
		"9999":                CheckQuad9DNS,
		"dns_root_servers":    CheckDNSRootServers,
	}
	checkName string         // name of the currently running check
	findings  []util.Finding // our findings
)

type checkFunction func()

// ExecuteChecks runs all the defined checks
func ExecuteChecks() {
	checksToDo := util.GetChecks()

	if len(checksToDo) == 0 {
		util.Log("main", util.LevelFatal, "NO_CHECKS", "No checks defined")
		return
	}

	for i := 0; i < len(checksToDo); i++ {
		if !execute(checksToDo[i]) {
			util.Log(
				"main",
				util.LevelFatal,
				"NO_SUCH_CHECK",
				"Unknown check '"+checksToDo[i],
			)
		}
	}
}

// execute runs one check
// @return boolean whether it was found and run
func execute(check string) bool {
	checkFunction, found := knownChecks[check]
	if found {
		checkName = check
		checkFunction()
	}
	return found
}
