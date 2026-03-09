package checks

import (
	"fmt"
	"netiscope/log"
	"netiscope/util"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
)

type NetiscopeCheck interface {
	Start()
	Stop()
	Log(level log.LogLevelType, mnemonic string, details string)
}

type netiscopeCheckBase struct {
	Name string
}

func (check *netiscopeCheckBase) Stop() {
}

func (check *netiscopeCheckBase) Log(
	level log.LogLevelType,
	mnemonic string,
	details string,
) {
	finding := log.NewFinding(check.Name, level, mnemonic, details)
	log.AllResults <- finding
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
}

type NetiscopeAdminCheck struct {
	netiscopeCheckBase
}

func (check NetiscopeAdminCheck) Start() {
}

var AdminCheck NetiscopeAdminCheck

func init() {
	AdminCheck = NetiscopeAdminCheck{
		netiscopeCheckBase: netiscopeCheckBase{
			Name: "admin",
		},
	}
}

var runningChecks []NetiscopeCheck

// ExecuteChecks runs all the defined checks
func ExecuteChecks(checksToDo []string) {
	if len(checksToDo) == 0 {
		AdminCheck.Log(log.LevelWarning, "NO_CHECKS", "No checks defined")
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
				check.Start()
			}(check)
		} else {
			AdminCheck.Log(log.LevelAdmin, "NO_SUCH_CHECK", fmt.Sprintf("No such check: %s", checksToDo[i]))
		}
	}
	wg.Wait()
}

func PrintResults() {
	levelCounter := make([]int, 7)
	for data := range log.AllResults {
		log.PrintResultItem(data)
		levelCounter[data.Level]++
	}

	summary := fmt.Sprintf(
		"DETAIL=%d,INFO=%d,WARNING=%d,ERROR=%d",
		levelCounter[log.LevelDetail],
		levelCounter[log.LevelInfo],
		levelCounter[log.LevelWarning],
		levelCounter[log.LevelError],
	)
	log.PrintResultItem(log.NewFinding("admin", log.LevelAdmin, "SUMMARY", summary))
}

func initializeCheckByName(name string) (NetiscopeCheck, bool) {
	data := netiscopeCheckBase{Name: name}
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
	default:
		return nil, false
	}
	return check, true
}

func Start() {
	AdminCheck.Log(log.LevelAdmin, "START", fmt.Sprintf("Started (version %s, %s)", util.Version, runtime.Version()))
}

func Finish(closeChannel bool) {
	AdminCheck.Log(log.LevelAdmin, "FINISH", "Finished")
	if closeChannel {
		close(log.AllResults)
	}
}

func Abort() {
	AdminCheck.Log(log.LevelAdmin, "ABORT", "Aborting checks")
	for _, check := range runningChecks {
		fmt.Println("checks: stopping", check)
		check.Stop()
	}
}

func showProgress(tracks map[string]int) {
	if !util.Verbose() {
		return
	}
	fmt.Fprint(os.Stderr, "\r")
	keys := make([]string, 0, len(tracks))
	for k := range tracks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	progress := []string{}
	for _, key := range keys {
		progress = append(progress, fmt.Sprintf("%d", tracks[key]))
	}
	fmt.Fprintf(os.Stderr, "PROGRESS=%s", strings.Join(progress, "/"))
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
		check.Log(
			log.LevelInfo,
			"PROVIDER_CIDR_UNKNOWN",
			fmt.Sprintf("CIDR block list is unknown for %s (IP: %v)", provider, ip),
		)
	case known && contains:
		check.Log(
			log.LevelInfo,
			"PROVIDER_CIDR_OK",
			fmt.Sprintf("The IP %s is in the CIDR block list for %s", ip, provider),
		)
	case known && !contains:
		check.Log(
			log.LevelWarning,
			"PROVIDER_CIDR_NOT_OK",
			fmt.Sprintf("The IP %s is not in the CIDR block list for %s", ip, provider),
		)
	}
}
