package measurements

import (
	"fmt"
	"time"

	"github.com/sparrc/go-ping"

	"netiscope/util"
)

// Ping pings (duh) a specific target
// Return: packet loss %
func Ping(check string, target string) float64 {

	var packetloss float64
	pinger, err := ping.NewPinger(target)
	if err != nil {
		panic(err)
	}

	pinger.OnRecv = func(pkt *ping.Packet) {
		util.Log(
			check,
			util.LevelDetail,
			"PING",
			fmt.Sprintf(
				"ping: %d bytes from %s: icmp_seq=%d time=%v ttl=%v",
				pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt, pkt.Ttl,
			),
		)
	}

	pinger.OnFinish = func(stats *ping.Statistics) {
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

	return packetloss
}
