/*
  A simple TCP+UDP "replier". It is far from perfect but it kinda works.
  It doesn't care what the client says. It just reponds with a short string.
  It must be run with parameters to specify the logfile, proto and port to listen on.

  For copyright, license, documentation, full source code and others see
  https://github.com/robert-kisteleki/netiscope
*/

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var (
	flagProto string
	flagPort  int
	flagLog   string
)

const response = "Netiscope\n"
const logMaxLen = 32

var (
	logFile *os.File
	logger  *log.Logger
)

var signalChannel = make(chan os.Signal, 1)

func logThis(localAddr string, remoteAddr string, data []byte, n int) {
	if n == 0 {
		logger.Printf("%s %v %v TIMEOUT", flagProto, localAddr, remoteAddr)
	} else {
		if n > logMaxLen {
			n = logMaxLen
		}
		logger.Printf("%s %v %v %+q", flagProto, localAddr, remoteAddr, data[:n])
	}
}

func handleTCP(conn net.Conn) {
	err := conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	if err != nil {
		fmt.Println(err)
		//return
	}
	buffer := make([]byte, 2048)
	var n int
	n, err = conn.Read(buffer[:]) // receive data, if any
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// time out
			logThis(conn.LocalAddr().String(), conn.RemoteAddr().String(), buffer, 0)
		} else {
			fmt.Println(err)
			//return
		}
	} else {
		logThis(conn.LocalAddr().String(), conn.RemoteAddr().String(), buffer, n)
	}
	conn.Write([]byte(response))
	conn.Close()
}

// we only care about SIGHUP - used to to re-open the logfile
// this facilitates log rotation
func signalHandler() {
	for {
		s := <-signalChannel
		switch s {
		case syscall.SIGHUP:
			// relatively easy: close the old log file, open a new one and use that from now on
			logFile.Close()
			var err error
			logFile, err = os.OpenFile(flagLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Println(err)
				//return
			}
			logger.SetOutput(logFile)
		}
	}
}

func main() {
	signal.Notify(signalChannel, syscall.SIGHUP)
	go signalHandler()

	flag.Usage = func() {
		fmt.Printf("Usage: %s [options]\n", os.Args[0])
		flag.PrintDefaults()
		return
	}
	flag.StringVar(&flagProto, "proto", "", "Listen using TCP or UDP")
	flag.IntVar(&flagPort, "port", 0, "What port to listen on")
	flag.StringVar(&flagLog, "log", "", "Log file to write to")
	flag.Parse()

	// insist on all parameters to be specified with reasonable values
	if flagProto == "" || flagPort == 0 || flagLog == "" {
		fmt.Printf("Usage: %s [options]\n", os.Args[0])
		flag.PrintDefaults()
		return
	}
	if flagProto != "UDP" && flagProto != "TCP" {
		fmt.Println("Protocol must be TCP or UDP")
		return
	}
	if flagPort <= 0 || flagPort >= 65536 {
		fmt.Println("Port nuber has to be between 0-65536")
		return
	}
	if flagLog == "" {
		fmt.Println("Log file must be some file name")
		return
	}

	// deal with logging
	var err error
	logFile, err = os.OpenFile(flagLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer logFile.Close()
	logger = log.New(logFile, "", log.LstdFlags|log.LUTC)

	// the TCP server is simple
	if flagProto == "TCP" {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", flagPort))
		if err != nil {
			fmt.Println(err)
			return
		}
		defer listener.Close()

		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Println(err)
				//return
			}
			go handleTCP(conn)
		}
	}

	// the UDP server is different
	if flagProto == "UDP" {
		pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", flagPort))
		if err != nil {
			fmt.Println(err)
			return
		}
		defer pc.Close()

		buffer := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buffer)
			if err != nil {
				fmt.Println(err)
				//return
			}
			logThis(pc.LocalAddr().String(), addr.String(), buffer, n)

			_, err = pc.WriteTo([]byte(response), addr)
			if err != nil {
				fmt.Println(err)
				//return
			}
		}
	}
}
