package checks

import (
	"fmt"
	"netiscope/log"
	"netiscope/util"
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
	var m sync.Mutex
	var counter []int = make([]int, 7)
	for i := 0; i < len(checksToDo); i++ {
		checkFunction, found := knownChecks[checksToDo[i]]
		if found {
			results := make(chan log.ResultItem)
			wg.Add(1)
			check := log.Check{Name: checksToDo[i], Collector: results}
			go checkFunction(check)
			go func(c chan log.ResultItem) {
				for v := range c {
					m.Lock()
					log.PrintResultItem(v)
					counter[v.Level]++
					m.Unlock()
				}
				wg.Done()
			}(results)
		}
	}
	wg.Wait()

	summary := fmt.Sprintf(
		"DETAIL=%d,INFO=%d,WARNING=%d,ERROR=%d",
		counter[log.LevelDetail],
		counter[log.LevelInfo],
		counter[log.LevelWarning],
		counter[log.LevelError],
	)
	log.PrintResultItem(log.NewFinding("main", log.LevelAdmin, "SUMMARY", summary))
}
