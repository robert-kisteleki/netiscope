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

type checkFunction func(log.Check)

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
func ExecuteChecks() {
	checksToDo := util.GetChecks()

	if len(checksToDo) == 0 {
		fmt.Println("No checks defined")
		return
	}

	var wg sync.WaitGroup
	var mutexr, mutext sync.Mutex
	levelCounter := make([]int, 7)
	checkCounter := make(map[string]int)
	for i := 0; i < len(checksToDo); i++ {
		checkName := checksToDo[i]
		checkFunction, found := knownChecks[checkName]
		if found {
			results := make(chan log.ResultItem)
			tracker := make(chan string)
			wg.Add(1)
			check := log.Check{Name: checkName, Collector: results, Tracker: tracker}
			go checkFunction(check)
			go func(c chan log.ResultItem) {
				for v := range c {
					mutexr.Lock()
					log.PrintResultItem(v)
					levelCounter[v.Level]++
					mutexr.Unlock()
				}
				wg.Done()
			}(results)
			go func(c chan string) {
				for check := range c {
					mutext.Lock()
					checkCounter[check]++
					showProgress(levelCounter, checkCounter)
					mutext.Unlock()
				}
			}(tracker)
		} else {
			log.PrintResultItem(log.NewFinding("main", log.LevelAdmin, "NO_CHECK", fmt.Sprintf("No such check: %s", checksToDo[i])))
		}
	}
	wg.Wait()

	fmt.Println()
	summary := fmt.Sprintf(
		"DETAIL=%d,INFO=%d,WARNING=%d,ERROR=%d",
		levelCounter[log.LevelDetail],
		levelCounter[log.LevelInfo],
		levelCounter[log.LevelWarning],
		levelCounter[log.LevelError],
	)
	log.PrintResultItem(log.NewFinding("main", log.LevelAdmin, "SUMMARY", summary))
}

func showProgress(levels []int, tracks map[string]int) {
	if !util.Verbose() {
		return
	}
	fmt.Fprint(os.Stderr, "\r")
	for i := 0; i < 4; i++ {
		fmt.Fprintf(os.Stderr, "%s=%d ", log.LogLevelType(i), levels[i])
	}
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
