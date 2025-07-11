package checks

import (
	"bufio"
	"fmt"
	"net"
	"netiscope/log"
	"netiscope/util"
	"strings"
	"time"
)

const expectedReply = "Netiscope\n"

// CheckPortFiltering checks if outgoing connections to various ports are allowed or not
func CheckPortFiltering(check *log.Check) {
	defer close(check.Tracker)

	targets := util.GetTargetsToPortCheck()
	for _, target := range targets {
		for _, af := range [2]string{"4", "6"} {
			if (af == "4" && !util.SkipIPv4()) || (af == "6" && !util.SkipIPv6()) {
				log.NewResultItem(check, log.LevelDetail, "PORT_FILTER_IPV"+af+"_DIAL",
					fmt.Sprintf("Connecting to %s:%s on IPv"+af+" %s", target[0], target[1], target[2]),
				)

				// try to connect
				conn, err := net.DialTimeout(
					strings.ToLower(target[2])+af, // {ud,tcp}{4,6}
					target[0]+":"+target[1],       // host:port
					time.Duration(util.GetPortFilteringTimeout())*time.Second,
				)
				if err != nil {
					log.NewResultItem(check, log.LevelError, "PORT_FILTER_IPV"+af+"_DIAL_ERROR",
						fmt.Sprintf("Error connecting to %s:%s on IPv"+af+" %s: %v", target[0], target[1], target[2], err),
					)
					log.Track(check)
					continue
				}

				// connection succesful
				log.NewResultItem(check, log.LevelInfo, "PORT_FILTER_IPV"+af+"_CONN_OK",
					fmt.Sprintf("Connection to %s:%s (%v) was successful on IPv"+af+" %s",
						target[0],
						target[1],
						conn.RemoteAddr().String(),
						target[2],
					),
				)

				// write & read
				conn.SetDeadline(time.Now().Add(time.Duration(util.GetPortFilteringTimeout()) * time.Second))
				fmt.Fprintf(conn, "Netiscope v%s\n", util.Version)
				reply, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					log.NewResultItem(check, log.LevelError, "PORT_FILTER_IPV"+af+"_READ_ERROR",
						fmt.Sprintf("Error reading from %s:%s on IPv"+af+" %s: %v", target[0], target[1], target[2], err),
					)
					log.Track(check)
					continue
				}

				// reply check, if enabled
				if util.CheckPortFilteringResponse() {
					if reply == expectedReply {
						log.NewResultItem(check, log.LevelInfo, "PORT_FILTER_IPV"+af+"_RESPONSE_GOOD",
							fmt.Sprintf("Got the expected reply from %s:%s on IPv"+af+" %s", target[0], target[1], target[2]),
						)
					} else {
						log.NewResultItem(check, log.LevelError, "PORT_FILTER_IPV"+af+"_RESPONSE_WRONG",
							fmt.Sprintf("Got unexpected reply from %s:%s on IPv"+af+" %s: %+q",
								target[0],
								target[1],
								target[2],
								reply,
							),
						)
					}
				}
				log.Track(check)
			}
		}
	}

	log.NewResultItem(check, log.LevelDetail, "FINISH", "Finished")
}
