/*
  Netiscope

  For copyright, license, doscumentation, full source and others see
  https://github.com/robert-kisteleki/netiscope
*/

package main

import (
	"netiscope/checks"
	"netiscope/util"
)

const (
	version = "0.0.1"
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
		"Started",
	)
}

func finish() {
	util.Log(
		"main",
		util.LevelInfo,
		"FINISH",
		"Finished",
	)
}
