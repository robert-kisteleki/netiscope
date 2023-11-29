/*
  Netiscope

  For copyright, license, documentation, full source code and others see
  https://github.com/robert-kisteleki/netiscope
*/

package main

import (
	"fmt"
	"netiscope/checks"
	"netiscope/log"
	"netiscope/util"
)

func main() {
	util.SetupFlags()
	util.ReadConfig()
	util.ReadCIDRConfig()
	log.SetLogLevel(util.GetLogLevel(), util.Verbose())
	reportNonStandardConfig()
	start()
	checks.ExecuteChecks()
	finish()
}

func reportNonStandardConfig() {
	if util.SkipIPv4() {
		log.PrintResultItem(
			log.NewFinding("main", log.LevelAdmin, "SKIP_IPV4", "IPv4 checks are disabled\n"),
		)
	}
	if util.SkipIPv6() {
		log.PrintResultItem(
			log.NewFinding("main", log.LevelAdmin, "SKIP_IPV6", "IPv6 checks are disabled\n"),
		)
	}
}

func start() {
	log.PrintResultItem(
		log.NewFinding("main", log.LevelAdmin, "START", fmt.Sprintf("Started (version %s)", util.Version)),
	)
}

func finish() {
	log.PrintResultItem(
		log.NewFinding("main", log.LevelAdmin, "FINISH", "Finished"),
	)
}
