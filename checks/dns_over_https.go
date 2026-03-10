package checks

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"netiscope/util"
)

// CheckDNSOverHTTPSProviders checks responsiveness of several DoH providers
type DNSOverHTTPSProvidersCheck struct {
	netiscopeCheckBase
}

// Start executes the DoH provider check
func (check *DNSOverHTTPSProvidersCheck) start() {
	check.netiscopeCheckBase.start()

	// the names to look up are in the config file
	names := util.GetDNSNamesToLookup()
	if len(names) == 0 {
		check.log(
			LogLevelFatal, "DOH_NO_NAMES",
			"The list of names to look up is empty",
		)
		return
	}

	// the providers (base URLs) to check up are in the config file
	providers := util.GetDoHProviders()
	for _, provider := range providers {
		if check.stopping {
			break
		}

		af := provider[0]
		format := provider[1]
		pbase := provider[2]

		if (af == "4" && !util.SkipIPv4()) || (af == "6" && !util.SkipIPv6()) {

			// loop over each name that needs to be looked up
			for _, name := range names {
				check.log(
					LogLevelDetail,
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
				req, err := http.NewRequest("GET", buildDoHQueryURL(check, format, pbase, qtype, name, true), nil)
				if err != nil {
					check.log(LogLevelError, "DOH_PROVIDER_REQUEST_ERROR", fmt.Sprintf("Error: %v", err))
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
					check.log(LogLevelError, "DOH_PROVIDER_GET_ERROR", fmt.Sprintf("Error: %v", err))
					continue
				}
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					check.log(LogLevelError, "DOH_PROVIDER_READ_ERROR", fmt.Sprintf("Error: %v", err))
					continue
				}

				// try to extract A and AAAA answers
				addrs, err := parseDoHResponse(check, format, body)
				if err != nil {
					check.log(
						LogLevelError,
						fmt.Sprintf("DOH_PROVIDER_LOOKUP_IPV%s_RESULT_ERROR", af),
						fmt.Sprintf("Error: %v", err),
					)
				}

				check.log(
					LogLevelInfo,
					fmt.Sprintf("DOH_PROVIDER_LOOKUP_IPV%s_RESULT_OK", af),
					fmt.Sprintf("Result for %s: %v", name, addrs),
				)

				// verify if answers are in predefined known CIDR ranges
				for _, ip := range addrs {
					CheckIPForProvider(&check.netiscopeCheckBase, fmt.Sprint(ip), name)
				}
			}
		}
	}

	check.netiscopeCheckBase.finish()
}

// given a format, the provider's base URL and the parameters, build the DoH query URL
func buildDoHQueryURL(
	check *DNSOverHTTPSProvidersCheck,
	format string,
	provider string,
	qtype string,
	name string,
	do bool,
) string {
	switch format {
	case "json":
		return fmt.Sprintf("%s?name=%s&type=%s&do=%v", provider, name, qtype, do)
	case "rfc8484":
		wire := CreateDNSQuery(&check.netiscopeCheckBase, name, qtype, true, true, true, true)
		return fmt.Sprintf("%s?dns=%s", provider, base64.RawURLEncoding.EncodeToString(wire))
	default:
		return ""
	}
}

// parse a DoH response, with a priori knowledge of what format was used
// @return a list of parsed addresses or an error
func parseDoHResponse(
	check *DNSOverHTTPSProvidersCheck,
	format string,
	responseBytes []byte,
) (addrs []string, err error) {
	switch format {
	case "json":
		return parseDoHJSONResponse(&check.netiscopeCheckBase, responseBytes)
	case "rfc8484":
		return parseDoHRFC8484Response(&check.netiscopeCheckBase, responseBytes)
	default:
		return
	}
}

// parse a JSON formatted DNS response
func parseDoHJSONResponse(
	check *netiscopeCheckBase,
	responseBytes []byte,
) (addrs []string, err error) {
	// this could be improved
	var result map[string]any
	json.Unmarshal([]byte(responseBytes), &result)

	switch result["Status"].(type) {
	case float64:
		// we report an error if the status was not 0 (NOERROR)
		status := int(result["Status"].(float64))
		if status != 0 {
			err = fmt.Errorf("result status is %d", status)
			return
		}
	default:
		err = fmt.Errorf("unable to find result status (is this a DoH URL?)")
		return
	}

	switch result["Answer"].(type) {
	case any:
		for _, answer := range result["Answer"].([]any) {
			ans := answer.(map[string]any)
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
func parseDoHRFC8484Response(
	check *netiscopeCheckBase,
	responseBytes []byte,
) (addrs []string, err error) {
	var parsed map[string][]string
	parsed, err = ParseDNSResponse(check, responseBytes)
	addrs = append(parsed["A"], parsed["AAAA"]...)
	return
}
