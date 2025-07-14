package checks

import (
	"fmt"
	"netiscope/log"
	"netiscope/util"
	"os"
	"sort"
	"strings"
	"sync"
)

type checkFunction func(*log.Check)

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
		"port_filtering":      CheckPortFiltering,
		"doh_providers":       CheckDNSOverHTTPSProviders,
	}
)

// ExecuteChecks runs all the defined checks
func ExecuteChecks(checksToDo []string, print bool) {
	if len(checksToDo) == 0 {
		fmt.Println("No checks defined")
		return
	}

	var wg sync.WaitGroup
	var mutex sync.Mutex
	checkCounter := make(map[string]int)
	checks := make([]*log.Check, 0)
	for i := 0; i < len(checksToDo); i++ {
		checkName := checksToDo[i]
		checkFunction, found := knownChecks[checkName]
		if found {
			results := make([]log.ResultItem, 0)
			tracker := make(chan string)
			wg.Add(1)
			check := &log.Check{Name: checkName, Collector: results, Tracker: tracker}
			checks = append(checks, check)

			go checkFunction(check)
			go func(c <-chan string) {
				for tick := range c {
					mutex.Lock()
					checkCounter[tick]++
					showProgress(checkCounter)
					mutex.Unlock()
				}
				wg.Done()
			}(tracker)
		} else {
			log.NewResultItem(log.AdminCheck, log.LevelAdmin, "NO_CHECK",
				fmt.Sprintf("No such check: %s", checksToDo[i]),
			)
		}
	}
	wg.Wait()

	if util.Verbose() {
		fmt.Println()
	}

	levelCounter := make([]int, 7)
	for _, check := range checks {
		for _, msg := range check.Collector {
			if print {
				log.PrintResultItem(msg)
			}
			levelCounter[msg.Level]++
		}
	}

	summary := fmt.Sprintf(
		"DETAIL=%d,INFO=%d,WARNING=%d,ERROR=%d",
		levelCounter[log.LevelDetail],
		levelCounter[log.LevelInfo],
		levelCounter[log.LevelWarning],
		levelCounter[log.LevelError],
	)
	log.NewResultItem(log.AdminCheck, log.LevelAdmin, "SUMMARY", summary)
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

func Start() {
	log.CreateAdminCheck()
	log.NewResultItem(log.AdminCheck, log.LevelAdmin, "START", fmt.Sprintf("Started (version %s)", util.Version))
}

func Finish(closeChannel bool) {
	log.NewResultItem(log.AdminCheck, log.LevelAdmin, "FINISH", "Finished")
	if closeChannel {
		close(log.AllResults)
	}
}
