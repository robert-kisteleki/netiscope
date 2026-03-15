package checks

import (
	"fmt"
	"netiscope/util"
	"strings"
)

type PathMTUHTTPCheck struct {
	netiscopeCheckBase
}

// PathMTUHTTPCheck checks if there is a likelyhood of IPv6 PMTUD problems
// by making HTTP reques	ts with different payload sizes and checking the responses
func (check *PathMTUHTTPCheck) start() {
	check.netiscopeCheckBase.start()

	if util.SkipIPv6() {
		check.log(LogLevelAdmin, "SKIP_IPV6", "IPv6 checks are disabled by configuration")
		check.netiscopeCheckBase.finish()
		return
	}

	// TODO: do these in parallel

	increases := []int{0, 100, 2000}
	var successes [][]bool
	successes = make([][]bool, len(increases))
	for i := range successes {
		successes[i] = make([]bool, len(increases))
	}

	timeout := util.GetPathMTUHTTPCheckTimeout()
	targets := util.GetTargetsToPathMTUHTTPCheck()
	for _, target := range targets {
		check.log(LogLevelDetail, "PATH_MTU_TARGET", "Checking path MTU for target "+target)
		for ipl, payload := range increases {
			for ipd, padding := range increases {
				if check.stopping {
					return
				}
				httpResponse, err := MakeAnchorHttpRequest(target, strings.Repeat("X", padding), payload, timeout)
				if err != nil {
					check.log(
						LogLevelDetail,
						"PATH_MTU_REQUEST_ERROR",
						fmt.Sprintf(
							"Error making HTTP request to %s with payload size %d and padding size %d: %v",
							target, payload, padding, err,
						),
					)
					successes[ipl][ipd] = false
					continue
				}
				check.log(
					LogLevelDetail,
					"PATH_MTU_RESPONSE",
					fmt.Sprintf(
						"Received response from %s with payload size %d and padding size %d: %s",
						target, payload, padding, httpResponse,
					),
				)
				successes[ipl][ipd] = true
			}
		}

		n := len(increases) - 1
		// heuristic: use the corners of the test matrix
		// TODO: this can be improved
		successes[0][n] = false
		switch {
		case successes[n][n]:
			check.log(LogLevelInfo, "PATH_MTU_SUCCESS", fmt.Sprintf("Path MTU check for %s successful", target))
		case !successes[0][0]:
			check.log(LogLevelWarning, "PATH_MTU_UNREACHABLE", fmt.Sprintf("Path MTU check for %s failed: target is down?", target))
		case !successes[0][n]:
			check.log(LogLevelError, "PATH_MTU_ERROR_FORWARD", fmt.Sprintf("Path MTU check for %s fails with large return packets. This may indicate PMTUD problems on the return path.", target))
		case !successes[n][0]:
			check.log(LogLevelError, "PATH_MTU_ERROR_RETURN", fmt.Sprintf("Path MTU check for %s fails with large outgoing packets. This may indicate PMTUD problems on the forward path.", target))
		default:
			check.log(LogLevelError, "PATH_MTU_ERROR_BOTH", fmt.Sprintf("Path MTU check for %s is mixed, there may be PMTUD problems.", target))
		}
	}

	check.netiscopeCheckBase.finish()
}
