/*
  Netiscope

  For copyright, license, documentation, full source code and others see
  https://github.com/robert-kisteleki/netiscope
*/

package main

import (
	"netiscope/checks"
	"netiscope/log"
	"netiscope/util"
)

func main() {
	util.SetupFlags()
	util.ReadConfig()
	util.ReadCIDRConfig()
	log.SetLogLevel(util.GetLogLevel(), util.Verbose())

	log.AllResults = make(chan log.ResultItem)

	if util.StartGui() {
		runGui()
	} else {
		go startChecks(util.GetChecks(), true)
		for data := range log.AllResults {
			log.PrintResultItem(data)
		}
	}
}

func startChecks(checksToDo []string, printAndClose bool) {
	checks.Start()
	if util.SkipIPv4() {
		log.NewResultItem(log.AdminCheck, log.LevelAdmin, "SKIP_IPV4", "IPv4 checks are disabled")
	}
	if util.SkipIPv6() {
		log.NewResultItem(log.AdminCheck, log.LevelAdmin, "SKIP_IPV6", "IPv6 checks are disabled")
	}
	checks.ExecuteChecks(checksToDo, printAndClose)
	checks.Finish(printAndClose)
}
