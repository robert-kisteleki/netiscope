package checks

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"netiscope/util"
)

// CheckDNSOverHTTPSProviders ...
func CheckDNSOverHTTPSProviders() {

	// the names to look up are in the config file
	names := util.GetDNSNamesToLookup()
	if len(names) == 0 {
		util.Log(
			checkName,
			util.LevelFatal,
			"DOH_NO_NAMES",
			"The list of names to look up is empty",
		)
		return
	}

	// the providers (base URLs) to check up are in the config file
	providers := util.GetDoHProviders()
	for _, provider := range providers {
		af := provider[0]
		pbase := provider[1]

		if (af == "4" && !util.SkipIPv4()) || (af == "6" && !util.SkipIPv6()) {

			// loop over each name that needs to be looked up
			for _, name := range names {

				util.Log(checkName, util.LevelDetail,
					fmt.Sprintf("DOH_PROVIDER_LOOKUP_IPV%s", af),
					fmt.Sprintf("Checking for name %s via %s using IPv%s", name, pbase, af),
				)

				// do A over IPv4 and AAAA over IPv6, which is not perfect but reasonable
				qtype := "A"
				if af == "6" {
					qtype = "AAAA"
				}

				// try to get some results
				client := &http.Client{}
				req, err := http.NewRequest("GET", buildDoHQueryURL(pbase, qtype, name, true), nil)
				if err != nil {
					util.Log(checkName, util.LevelError, "DOH_PROVIDER_REQUEST_ERROR", fmt.Sprintf("%v", err))
					continue
				}
				req.Header.Add("Accept", "application/dns-json")
				resp, err := client.Do(req)
				if err != nil {
					util.Log(checkName, util.LevelError, "DOH_PROVIDER_GET_ERROR", fmt.Sprintf("%v", err))
					continue
				}
				defer resp.Body.Close()
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					util.Log(checkName, util.LevelError, "DOH_PROVIDER_READ_ERROR", fmt.Sprintf("%v", err))
					continue
				}

				// this could be improved
				var result map[string]interface{}
				json.Unmarshal([]byte(body), &result)

				// try to extract A and AAAA answers
				var addrs []string
				switch result["Answer"].(type) {
				case interface{}:
					for _, answer := range result["Answer"].([]interface{}) {
						ans := answer.(map[string]interface{})
						rtype := int(ans["type"].(float64))
						if rtype == 1 || rtype == 28 {
							addrs = append(addrs, ans["data"].(string))
						}
					}
				default:
					// like nil
				}

				// we report an error if the status was not 0 (NOERROR)
				var level util.LogLevelType = util.LevelInfo
				switch result["Status"].(type) {
				case float64:
					if int(result["Status"].(float64)) != 0 {
						level = util.LevelError
					}
					util.Log(checkName, level,
						fmt.Sprintf("DOH_PROVIDER_LOOKUP_IPV%s_RESULT", af),
						fmt.Sprintf(
							"Result for %s: status=%d, AD=%v, addrs=%v",
							name,
							int(result["Status"].(float64)),
							result["AD"].(bool),
							addrs,
						),
					)
				default:
					util.Log(checkName, util.LevelError,
						fmt.Sprintf("DOH_PROVIDER_LOOKUP_IPV%s_RESULT", af),
						fmt.Sprintf(
							"Result for %s: unable to find result status (is this a DoH server?)",
							name,
						),
					)
				}

				// verify if answers are in predefined known CIDR ranges
				for _, ip := range addrs {
					util.CheckIPForProvider(checkName, fmt.Sprint(ip), name)
				}
			}
		}
	}
}

// given a provider's base URL and the parameters, build the DoH query URL
func buildDoHQueryURL(provider string, qtype string, name string, do bool) string {
	return fmt.Sprintf("%s?name=%s&type=%s&do=%v", provider, name, qtype, do)
}
