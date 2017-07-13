package main

import (
	"fmt"
	"net"
	"syscall"

	"math/rand"
	"time"

	"flag"

	"os"

	"os/signal"

	"eplight.org/godhcpd/internal"
)

func createPools() ([]internal.Pool, map[int]*internal.Pool) {
	pools := make([]internal.Pool, len(internal.GlobalConfig.Pools))
	mapping := make(map[int]*internal.Pool)

	i := 0

	for name, conf := range internal.GlobalConfig.Pools {
		fmt.Print("Creating pool ", name, ": ")
		pools[i] = internal.NewPool(&conf)

		for _, str := range conf.Interfaces {
			iface, _ := net.InterfaceByName(str)

			fmt.Print(iface.Name, ", ")

			mapping[iface.Index] = &pools[i]
		}

		fmt.Print("\n")

		i++
	}

	return pools, mapping
}

func main() {
	// random seed
	rand.Seed(time.Now().Unix())

	// flags
	configFileName := flag.String("config", "godhcpd.toml", "Configuration file")
	help := flag.Bool("help", false, "Display help")
	flag.Parse()

	if *help {
		flag.Usage()
		return
	}

	// configuration
	internal.LoadGlobalConfig(*configFileName)

	// we need to bind to all to receive broadcasts
	addr, _ := net.ResolveUDPAddr("udp4", ":67")
	sock, err := net.ListenUDP("udp4", addr)

	if err != nil {
		fmt.Println("Cannot create UDP listening socket", err)
		return
	}

	defer sock.Close()

	if err := internal.EnablePktInfo(sock); err != nil {
		fmt.Println("Cannot enable IP_PKTINFO", err)
		return
	}

	receiver := internal.UDPReceiver(sock)
	sender := internal.UDPSender(sock)
	signals := make(chan os.Signal, 10)
	defer close(signals)
	defer close(sender)

	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

	pools, mapping := createPools()

	for i := range pools {
		go pools[i].Run(sender)
		defer close(pools[i].Receiver)
	}

	fmt.Println("Entering main loop")

MainLoop:
	for {
		select {
		case msg, more := <-receiver:
			if !more {
				fmt.Println("UDP receiver socket error")
				break MainLoop
			}

			p, found := mapping[msg.Interface.Index]

			if !found {
				fmt.Println("Ignoring packet from interface:", msg.Interface.Name)
				break
			}

			fmt.Println(">>>>>")
			fmt.Println("Received packet from interface:", msg.Interface.Name)

			internal.DebugDHCPMessage(&msg.Message)

			p.Receiver <- msg

		case sig := <-signals:
			fmt.Println("Signal received: ", sig)
			break MainLoop
		}
	}

	fmt.Println("Exiting main loop")
}
