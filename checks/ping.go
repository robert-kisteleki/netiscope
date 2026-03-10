package checks

import (
	"fmt"
	"time"

	"netiscope/util"

	probing "github.com/prometheus-community/pro-bing"
)

// Ping (duh) a specific target using our favourite library
// return a ReultCode
func Ping(
	check *netiscopeCheckBase,
	target string,
	mnemo string,
) (result ResultCode) {
	check.log(
		LogLevelInfo,
		fmt.Sprintf("PING_%s", mnemo),
		fmt.Sprintf("Pinging %s", target),
	)

	var packetloss float64
	pinger, err := probing.NewPinger(target)
	if err != nil {
		panic(err)
	}

	pinger.OnRecv = func(pkt *probing.Packet) {
		check.log(
			LogLevelDetail,
			"PING_PACKET",
			fmt.Sprintf(
				"ping: %d bytes from %s: icmp_seq=%d time=%v ttl=%v",
				pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.TTL,
			),
		)
	}

	pinger.OnFinish = func(stats *probing.Statistics) {
		packetloss = stats.PacketLoss
		check.log(
			LogLevelDetail,
			"PING_RESULTS",
			fmt.Sprintf(
				"%d packets transmitted, %d packets received, %v%% packet loss",
				stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss),
		)
		check.log(
			LogLevelDetail,
			"PING_STATS",
			fmt.Sprintf(
				"round-trip min/avg/max/stddev = %v/%v/%v/%v",
				stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt),
		)
	}

	pinger.Count = util.GetPingCount()
	pinger.Timeout = time.Duration(util.GetPingCount()) * time.Second
	pinger.Run()

	switch {
	case packetloss == 0.0:
		check.log(
			LogLevelInfo,
			fmt.Sprintf("PING_%s_WORKS", mnemo),
			fmt.Sprintf("Server %s is reachable", target),
		)
		return ResultSuccess
	case packetloss == 100.0:
		check.log(
			LogLevelWarning,
			fmt.Sprintf("PING_%s_FAILS", mnemo),
			fmt.Sprintf("Server %s is not reachable", target),
		)
		return ResultFailure
	default:
		check.log(
			LogLevelWarning,
			fmt.Sprintf("PING_%s_WARNING", mnemo),
			fmt.Sprintf("Server %s shows packet loss", target),
		)
		return ResultPartial
	}
}

// PingServers pings a set of servers
// return a MultipleResult
func PingServers(
	check *netiscopeCheckBase,
	mnemo string,
	resolvers []string,
) (outcollector MultipleResult) {
	for _, resolver := range resolvers {
		if check.stopping {
			return
		}
		pingResult := Ping(check, resolver, mnemo)
		outcollector[pingResult]++
	}

	return
}
