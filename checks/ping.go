package checks

import (
	"fmt"
	"time"

	"netiscope/log"
	"netiscope/util"

	probing "github.com/prometheus-community/pro-bing"
)

// Ping (duh) a specific target using our favourite library
// return a ReultCode
func Ping(
	check *log.Check,
	target string,
	mnemo string,
) (result ResultCode) {
	log.NewResultItem(
		check,
		log.LevelInfo,
		fmt.Sprintf("PING_%s", mnemo),
		fmt.Sprintf("Pinging %s", target),
	)

	var packetloss float64
	pinger, err := probing.NewPinger(target)
	if err != nil {
		panic(err)
	}

	pinger.OnRecv = func(pkt *probing.Packet) {
		log.NewResultItem(
			check,
			log.LevelDetail,
			"PING_PACKET",
			fmt.Sprintf(
				"ping: %d bytes from %s: icmp_seq=%d time=%v ttl=%v",
				pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.TTL,
			),
		)
	}

	pinger.OnFinish = func(stats *probing.Statistics) {
		packetloss = stats.PacketLoss
		log.NewResultItem(
			check,
			log.LevelDetail,
			"PING_RESULTS",
			fmt.Sprintf(
				"%d packets transmitted, %d packets received, %v%% packet loss",
				stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss),
		)
		log.NewResultItem(
			check,
			log.LevelDetail,
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
		log.NewResultItem(
			check,
			log.LevelInfo,
			fmt.Sprintf("PING_%s_WORKS", mnemo),
			fmt.Sprintf("Server %s is reachable", target),
		)
		return ResultSuccess
	case packetloss == 100.0:
		log.NewResultItem(
			check,
			log.LevelWarning,
			fmt.Sprintf("PING_%s_FAILS", mnemo),
			fmt.Sprintf("Server %s is not reachable", target),
		)
		return ResultFailure
	default:
		log.NewResultItem(
			check,
			log.LevelWarning,
			fmt.Sprintf("PING_%s_WARNING", mnemo),
			fmt.Sprintf("Server %s shows packet loss", target),
		)
		return ResultPartial
	}
}

// PingServers pings a set of servers
// return a MultipleResult
func PingServers(
	check *log.Check,
	mnemo string,
	resolvers []string,
) (outcollector MultipleResult) {
	for _, resolver := range resolvers {
		pingResult := Ping(check, resolver, mnemo)
		outcollector[pingResult]++
	}

	return
}
