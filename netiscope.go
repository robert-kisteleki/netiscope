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
	"runtime"
)

func main() {
	util.SetupFlags()

	if util.VersionFlag() {
		fmt.Println(util.Version + " (" + runtime.Version() + ")")
		return
	}

	util.ReadConfig()
	util.ReadCIDRConfig()
	checks.SetLogLevel(util.GetLogLevel(), util.Verbose())

	if util.StartGui() {
		runGui()
	} else {
		go startChecks(util.GetChecks(), true)
		checks.PrintResults()
	}
}

func startChecks(checksToDo []string, close bool) {
	checks.Start()
	if util.SkipIPv4() {
		checks.AdminCheck.Log(checks.LogLevelAdmin, "SKIP_IPV4", "IPv4 checks are disabled")
	}
	if util.SkipIPv6() {
		checks.AdminCheck.Log(checks.LogLevelAdmin, "SKIP_IPV6", "IPv6 checks are disabled")
	}
	checks.ExecuteChecks(checksToDo)
	checks.Finish(close)
}
