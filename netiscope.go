/*
  Netiscope

  For copyright, license, documentation, full source code and others see
  https://github.com/robert-kisteleki/netiscope
*/

package main

import (
	"fmt"
	"netiscope/checks"
	"netiscope/util"
)

func main() {
	util.SetupFlags()
	util.ReadConfig()
	util.ReadCIDRConfig()
	reportNonStandardConfig()
	start()
	checks.ExecuteChecks()
	finish()
}

func reportNonStandardConfig() {
	if util.SkipIPv4() {
		util.Log(
			"main",
			util.LevelInfo,
			"SKIP_IPV4",
			"IPv4 checks are disabled",
		)
	}
	if util.SkipIPv6() {
		util.Log(
			"main",
			util.LevelInfo,
			"SKIP_IPV6",
			"IPv6 checks are disabled",
		)
	}
}

func start() {
	util.Log(
		"main",
		util.LevelInfo,
		"START",
		fmt.Sprintf("Started (version %s)", util.Version),
	)
}

func finish() {
	util.ReportLogTotals()
	util.Log(
		"main",
		util.LevelInfo,
		"FINISH",
		"Finished",
	)
}
