package internal

import (
	"fmt"
	"net"
)

type DirectedDHCPMessage struct {
	Message   DHCPMessage
	Interface *net.Interface
	Remote    *net.UDPAddr
}

func UDPReceiver(sock *net.UDPConn) <-chan DirectedDHCPMessage {
	channel := make(chan DirectedDHCPMessage, 10)

	go func() {
		for {
			buffer := make([]byte, 576)

			_, _, addr, pktInfo, err := ReadUDPWithPktInfo(sock, buffer)

			if err != nil {
				fmt.Println("Error while reading UDP message:", err)
				break
			}

			iface, _ := net.InterfaceByIndex(int(pktInfo.Ifindex))
			dhcp, err := UnmarshallDHCPMessage(buffer)

			if err != nil {
				fmt.Println("Unable to parse DHCP message:", err)
			}

			channel <- DirectedDHCPMessage{
				Interface: iface,
				Message:   dhcp,
				Remote:    addr,
			}
		}

		close(channel)
	}()

	return channel
}

func UDPSender(sock *net.UDPConn) chan<- DirectedDHCPMessage {
	channel := make(chan DirectedDHCPMessage, 10)

	go func() {
		sendAddr, _ := net.ResolveUDPAddr("udp4", "255.255.255.255:68")

		for msg := range channel {
			bytes, err := MarshallDHCPMessage(msg.Message)

			if err != nil {
				fmt.Println("Unable to create DHCP message:", err)
				continue
			}

			_, err = WriteUDPWithInterface(sock, bytes, sendAddr, int32(msg.Interface.Index))

			if err != nil {
				fmt.Println("Unable to send DHCP message:", err)
				continue
			}
		}
	}()

	return channel
}
