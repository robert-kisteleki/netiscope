package checks

import (
	"fmt"
	"netiscope/util"
	"runtime"
	"strings"
	"sync"
)

func init() {
	AllResults = make(chan ResultItem)
}

type NetiscopeCheck interface {
	start()
	stop()
	log(level LogLevelType, mnemonic string, details string)
	finish()
	getNameAsMnemonic() string
}

type netiscopeCheckBase struct {
	name     string
	stopping bool
	running  bool
}

func (check *netiscopeCheckBase) start() {
	check.log(
		LogLevelInfo,
		check.getNameAsMnemonic()+"_START",
		"Starting check",
	)
	check.running = true
}

func (check *netiscopeCheckBase) stop() {
	if check.running {
		check.log(
			LogLevelInfo,
			check.getNameAsMnemonic()+"_STOP",
			"Trying to stop the check",
		)
		check.stopping = true
	}
}

func (check *netiscopeCheckBase) log(
	level LogLevelType,
	mnemonic string,
	details string,
) {
	AllResults <- NewFinding(check.name, level, mnemonic, details)
}

func (check *netiscopeCheckBase) finish() {
	check.log(
		LogLevelInfo,
		check.getNameAsMnemonic()+"_FINISH",
		"Finished",
	)
	check.running = false
}

func (check *netiscopeCheckBase) getNameAsMnemonic() string {
	return strings.ToUpper(check.name)
}

// what checks are available
var knownChecks []string = []string{
	"network_interfaces",
	"dns_local_resolvers",
	"dns_open_resolver_1111",
	"dns_open_resolver_8888",
	"dns_open_resolver_9999",
	"dns_root_servers",
	"port_filtering",
	"doh_providers",
	"ssh_host_keys",
	"path_mtu",
}

var runningChecks []NetiscopeCheck

// ExecuteChecks runs all the defined checks
func ExecuteChecks(checksToDo []string) {
	if len(checksToDo) == 0 {
		AdminCheck.log(LogLevelWarning, "NO_CHECKS", "No checks defined")
		return
	}

	var wg sync.WaitGroup
	runningChecks = make([]NetiscopeCheck, 0)
	for i := range checksToDo {
		checkName := checksToDo[i]
		check, found := initializeCheckByName(checkName)
		if found {
			wg.Add(1)
			runningChecks = append(runningChecks, check)

			go func(check NetiscopeCheck) {
				defer wg.Done()
				check.start()
			}(check)
		} else {
			AdminCheck.log(LogLevelAdmin, "NO_SUCH_CHECK", fmt.Sprintf("No such check: %s", checksToDo[i]))
		}
	}
	wg.Wait()
}

func PrintResults() {
	jsonFormat := util.UseJSONFormat()
	levelCounter := make([]int, 7)
	for data := range AllResults {
		PrintResultItem(data, jsonFormat)
		levelCounter[data.Level]++
	}

	summary := fmt.Sprintf(
		"DETAIL=%d,INFO=%d,WARNING=%d,ERROR=%d",
		levelCounter[LogLevelDetail],
		levelCounter[LogLevelInfo],
		levelCounter[LogLevelWarning],
		levelCounter[LogLevelError],
	)
	PrintResultItem(NewFinding("admin", LogLevelAdmin, "SUMMARY", summary), jsonFormat)
}

func initializeCheckByName(name string) (NetiscopeCheck, bool) {
	data := netiscopeCheckBase{name: name}
	var check NetiscopeCheck
	switch name {
	case "network_interfaces":
		check = &NetworkInterfacesCheck{netiscopeCheckBase: data}
	case "dns_local_resolvers":
		check = &DNSLocalResolversCheck{netiscopeCheckBase: data}
	case "dns_open_resolver_1111":
		check = &DNSCloudflareOpenResolverCheck{netiscopeCheckBase: data}
	case "dns_open_resolver_8888":
		check = &DNSGoogleOpenResolverCheck{netiscopeCheckBase: data}
	case "dns_open_resolver_9999":
		check = &DNSQuad9OpenResolverCheck{netiscopeCheckBase: data}
	case "dns_root_servers":
		check = &DNSRootServersCheck{netiscopeCheckBase: data}
	case "port_filtering":
		check = &PortFilteringCheck{netiscopeCheckBase: data}
	case "doh_providers":
		check = &DNSOverHTTPSProvidersCheck{netiscopeCheckBase: data}
	case "ssh_host_keys":
		check = &SSHHostKeysCheck{netiscopeCheckBase: data}
	case "path_mtu_http":
		check = &PathMTUHTTPCheck{netiscopeCheckBase: data}
	default:
		return nil, false
	}
	return check, true
}

func Start() {
	AdminCheck.log(LogLevelAdmin, "START", fmt.Sprintf("Started (version %s, %s)", util.Version, runtime.Version()))
}

func Finish(closeChannel bool) {
	AdminCheck.log(LogLevelAdmin, "FINISH", "Finished")
	if closeChannel {
		close(AllResults)
	}
}

func Stop() {
	AdminCheck.log(LogLevelAdmin, "STOP", "Stopping checks")
	for _, check := range runningChecks {
		check.stop()
	}
}

// CheckIPForProvider makes log entries about an IP being in a provider's CIDR list
func CheckIPForProvider(
	check *netiscopeCheckBase,
	ip string,
	provider string,
) {
	known, contains := util.IsIPInProviderCIDRBlock(ip, provider)
	switch {
	case !known:
		check.log(
			LogLevelInfo,
			"PROVIDER_CIDR_UNKNOWN",
			fmt.Sprintf("CIDR block list is unknown for %s (IP: %v)", provider, ip),
		)
	case known && contains:
		check.log(
			LogLevelInfo,
			"PROVIDER_CIDR_OK",
			fmt.Sprintf("The IP %s is in the CIDR block list for %s", ip, provider),
		)
	case known && !contains:
		check.log(
			LogLevelWarning,
			"PROVIDER_CIDR_NOT_OK",
			fmt.Sprintf("The IP %s is not in the CIDR block list for %s", ip, provider),
		)
	}
}
