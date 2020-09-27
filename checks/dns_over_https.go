package checks

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"netiscope/measurements"
	"netiscope/util"
)

// CheckDNSOverHTTPSProviders checks responsiveness of several DoH providers
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
		format := provider[1]
		pbase := provider[2]

		if (af == "4" && !util.SkipIPv4()) || (af == "6" && !util.SkipIPv6()) {

			// loop over each name that needs to be looked up
			for _, name := range names {

				util.Log(checkName, util.LevelDetail,
					fmt.Sprintf("DOH_PROVIDER_LOOKUP_IPV%s", af),
					fmt.Sprintf("Checking for name %s via %s (format: %s) using IPv%s", name, pbase, format, af),
				)

				// do A over IPv4 and AAAA over IPv6, which is not perfect but reasonable
				qtype := "A"
				if af == "6" {
					qtype = "AAAA"
				}

				// try to get some results
				client := &http.Client{}
				req, err := http.NewRequest("GET", buildDoHQueryURL(format, pbase, qtype, name, true), nil)
				if err != nil {
					util.Log(checkName, util.LevelError, "DOH_PROVIDER_REQUEST_ERROR", fmt.Sprintf("Error: %v", err))
					continue
				}
				switch format {
				case "json":
					req.Header.Add("Accept", "application/dns-json")
				case "rfc8484":
					req.Header.Add("Accept", "application/dns-message")
				}
				resp, err := client.Do(req)
				if err != nil {
					util.Log(checkName, util.LevelError, "DOH_PROVIDER_GET_ERROR", fmt.Sprintf("Error: %v", err))
					continue
				}
				defer resp.Body.Close()
				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					util.Log(checkName, util.LevelError, "DOH_PROVIDER_READ_ERROR", fmt.Sprintf("Error: %v", err))
					continue
				}

				// try to extract A and AAAA answers
				addrs, err := parseDoHResponse(format, body)
				if err != nil {
					util.Log(checkName, util.LevelError,
						fmt.Sprintf("DOH_PROVIDER_LOOKUP_IPV%s_RESULT_ERROR", af),
						fmt.Sprintf("Error: %v", err),
					)
				}

				util.Log(checkName, util.LevelInfo,
					fmt.Sprintf("DOH_PROVIDER_LOOKUP_IPV%s_RESULT_OK", af),
					fmt.Sprintf("Result for %s: %v", name, addrs),
				)

				// verify if answers are in predefined known CIDR ranges
				for _, ip := range addrs {
					util.CheckIPForProvider(checkName, fmt.Sprint(ip), name)
				}
			}
		}
	}
}

// given a format, the provider's base URL and the parameters, build the DoH query URL
func buildDoHQueryURL(format string, provider string, qtype string, name string, do bool) string {
	switch format {
	case "json":
		return fmt.Sprintf("%s?name=%s&type=%s&do=%v", provider, name, qtype, do)
	case "rfc8484":
		wire := measurements.CreateDNSQuery(name, qtype, true, true, true, true)
		return fmt.Sprintf("%s?dns=%s", provider, base64.RawURLEncoding.EncodeToString(wire))
	default:
		return ""
	}
}

// parse a DoH response, with a priori knowledge of what format was used
// @return a list of parsed addresses or an error
func parseDoHResponse(format string, responseBytes []byte) (addrs []string, err error) {
	switch format {
	case "json":
		return parseDoHJSONResponse(responseBytes)
	case "rfc8484":
		return parseDoHRFC8484Response(responseBytes)
	default:
		return
	}
}

// parse a JSON formatted DNS response
func parseDoHJSONResponse(responseBytes []byte) (addrs []string, err error) {
	// this could be improved
	var result map[string]interface{}
	json.Unmarshal([]byte(responseBytes), &result)

	switch result["Status"].(type) {
	case float64:
		// we report an error if the status was not 0 (NOERROR)
		status := int(result["Status"].(float64))
		if status != 0 {
			err = fmt.Errorf("Result status is %d", status)
			return
		}
	default:
		err = fmt.Errorf("Unable to find result status (is this a DoH URL?)")
		return
	}

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
		// like nil or such
	}

	return
}

// parse an RFC8484 formatted response
func parseDoHRFC8484Response(responseBytes []byte) (addrs []string, err error) {
	var parsed map[string][]string
	parsed, err = measurements.ParseDNSResponse(responseBytes)
	addrs = append(parsed["A"], parsed["AAAA"]...)
	return
}
