package measurements

import (
	"fmt"
	"time"

	"netiscope/util"

	probing "github.com/prometheus-community/pro-bing"
)

// Ping (duh) a specific target using our favourite library
// return a ReultCode
func Ping(check string, target string, mnemo string) (results ResultCode) {
	util.Log(
		check,
		util.LevelInfo,
		fmt.Sprintf("PING_%s", mnemo),
		fmt.Sprintf("Pinging %s", target),
	)

	var packetloss float64
	pinger, err := probing.NewPinger(target)
	if err != nil {
		panic(err)
	}

	pinger.OnRecv = func(pkt *probing.Packet) {
		util.Log(
			check,
			util.LevelDetail,
			"PING_PACKET",
			fmt.Sprintf(
				"ping: %d bytes from %s: icmp_seq=%d time=%v ttl=%v",
				pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.TTL,
			),
		)
	}

	pinger.OnFinish = func(stats *probing.Statistics) {
		packetloss = stats.PacketLoss
		util.Log(
			check,
			util.LevelDetail,
			"PING_RESULTS",
			fmt.Sprintf(
				"%d packets transmitted, %d packets received, %v%% packet loss",
				stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss),
		)
		util.Log(
			check,
			util.LevelDetail,
			"PING_STATS",
			fmt.Sprintf(
				"round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
				stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt),
		)
	}

	pinger.Count = util.GetPingCount()
	pinger.Timeout = time.Duration(util.GetPingCount()) * time.Second
	pinger.Run()

	switch {
	case packetloss == 0.0:
		util.Log(
			check,
			util.LevelInfo,
			fmt.Sprintf("PING_%s_WORKS", mnemo),
			fmt.Sprintf("Server %s is reachable", target),
		)
		return ResultSuccess
	case packetloss == 100.0:
		util.Log(
			check,
			util.LevelWarning,
			fmt.Sprintf("PING_%s_FAILS", mnemo),
			fmt.Sprintf("Server %s is not reachable", target),
		)
		return ResultFailure
	default:
		util.Log(
			check,
			util.LevelWarning,
			fmt.Sprintf("PING_%s_WARNING", mnemo),
			fmt.Sprintf("Server %s shows packet loss", target),
		)
		return ResultPartial
	}
}

// PingServers pings a set of servers
// return a MultipleResult
func PingServers(check string, mnemo string, resolvers []string) (results MultipleResult) {
	for _, resolver := range resolvers {
		pingResult := Ping(check, resolver, mnemo)
		results[pingResult]++
	}

	return
}
