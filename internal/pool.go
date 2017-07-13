package internal

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"
)

type LeaseState int
type AddressSelectAlgorithm int

const (
	LeaseReserved LeaseState = iota
	LeaseInUse    LeaseState = iota
)

const (
	Sequential AddressSelectAlgorithm = iota
	Randomized AddressSelectAlgorithm = iota
)

type ClientIdentifier struct {
	ID  []uint8
	Mac net.HardwareAddr
}

type Lease struct {
	Address net.IP
	State   LeaseState
	ID      ClientIdentifier
	Expires time.Time
}

type LeaseMap map[uint32]*Lease

type Pool struct {
	Leases    LeaseMap
	Network   net.IPNet
	Start     uint32
	End       uint32
	Lifetime  time.Duration
	Algorithm AddressSelectAlgorithm
	Receiver  chan DirectedDHCPMessage
}

func NewPool(conf *PoolConfig) Pool {
	algo := Randomized

	switch conf.Algorithm {
	case "sequential":
		algo = Sequential

	case "random":
		algo = Randomized
	}

	start := conf.Start
	end := conf.End

	_, n, _ := net.ParseCIDR(conf.Network)
	dur, _ := time.ParseDuration(conf.Lifetime)

	return Pool{
		Leases:    make(LeaseMap),
		Network:   *n,
		Start:     uint32(start),
		End:       uint32(end),
		Algorithm: algo,
		Receiver:  make(chan DirectedDHCPMessage, 10),
		Lifetime:  dur,
	}
}

func (pool *Pool) Run(sender chan<- DirectedDHCPMessage) {
	ticker := time.NewTicker(time.Second * 10)

RunLoop:
	for {
		select {
		case <-ticker.C:
			pool.expireOld()
		case msg, more := <-pool.Receiver:
			if !more {
				break RunLoop
			}

			fmt.Println("<<<<<")

			t := msg.Message.Type()

			// some basic validation

			if err := basicValidation(&msg, t); err != nil {
				fmt.Println("Error while validating DHCP message:", err)
				break
			}

			switch t {
			case DHCPDiscover:
				fmt.Println("Handling DHCPDiscover")
				pool.handleDiscover(&msg, sender)
			case DHCPRequest:
				fmt.Println("Handling DHCPRequest")
				pool.handleRequest(&msg, sender)
			case DHCPDecline:
				fmt.Println("Handling DHCPDecline")
				pool.handleDecline(&msg, sender)
			case DHCPRelease:
				fmt.Println("Handling DHCPRelease")
				pool.handleRelease(&msg, sender)
			case DHCPInform:
				fmt.Println("Handling DHCPInform")
				pool.handleInform(&msg, sender)
			default:
				fmt.Println("Unknown DHCP message type")
			}
		}
	}

	ticker.Stop()
}

func basicValidation(msg *DirectedDHCPMessage, t DHCPType) error {
	if msg.Message.BootpOperation != BootRequest {
		return errors.New("Operation is not BOOTREQUEST")
	}

	if msg.Message.HwAddrType != BootpEthernet {
		return errors.New("Only supported HwType is Ethernet")
	}

	// if (msg.Message.Flags & BootpBroadcast) == 0 {
	// return errors.New("Broadcast flag not set")
	// }

	return nil
}

func (pool *Pool) expireOld() {
	for i, lease := range pool.Leases {
		if lease.Expires.Before(time.Now()) {
			delete(pool.Leases, i)
			fmt.Println("Expiration, freeing ", lease.Address)
		}
	}
}

func (pool *Pool) handleDiscover(msg *DirectedDHCPMessage, sender chan<- DirectedDHCPMessage) {
	clientID := newClientIdentifier(&msg.Message)
	serverIP := pool.serverIP(msg.Interface)

	// find lease for client or reserve new one
	lease, found := pool.findClientLease(&clientID)
	if !found {
		fmt.Println("Lease not found, trying to reserve new one ...")
		free := pool.freeIndices()

		if len(free) == 0 {
			fmt.Println("No addresses free, aborting!")
			// no addresses free, ignore!
			return
		}

		idx := selectNumber(pool.Algorithm, free)

		pool.Leases[idx] = &Lease{
			Address: pool.addressFromIndex(idx),
			ID:      clientID,
			State:   LeaseReserved,
		}

		lease = pool.Leases[idx]

		fmt.Println("Lease reserved", msg.Message.ClientHwAddr, pool.Leases[idx].Address)
	}

	// build reply
	offer := BuildBasicReply(&msg.Message, serverIP)
	offer.YourIP = lease.Address

	offer.Options[DHCPMessageTypeOptionCode] = &Uint8DHCPOption{
		Value: []uint8{
			uint8(DHCPOffer),
		},
	}
	offer.Options[SubnetMaskOptionCode] = &IPDHCPOption{
		Value: []net.IP{
			net.IPv4(pool.Network.Mask[0], pool.Network.Mask[1], pool.Network.Mask[2], pool.Network.Mask[3]),
		},
	}
	offer.Options[RouterOptionCode] = &IPDHCPOption{
		Value: []net.IP{
			serverIP,
		},
	}
	offer.Options[DomainNameServerOptionCode] = &IPDHCPOption{
		Value: []net.IP{
			serverIP,
		},
	}
	offer.Options[IPAddressLeaseTimeOptionCode] = &DurationDHCPOption{
		Value: pool.Lifetime,
	}

	fmt.Println("Sending offer")
	DebugDHCPMessage(&offer)

	sender <- DirectedDHCPMessage{
		Message:   offer,
		Interface: msg.Interface,
		Remote:    msg.Remote,
	}
}

func (pool *Pool) handleRequest(msg *DirectedDHCPMessage, sender chan<- DirectedDHCPMessage) {
	clientID := newClientIdentifier(&msg.Message)
	serverIP := pool.serverIP(msg.Interface)
	selectedServer := msg.Message.ServerIdentifier()
	requestedIP := msg.Message.RequestedIP()

	if requestedIP == nil {
		if msg.Message.ClientIP.Equal(net.IPv4zero) {
			fmt.Println("DHCPRequest bez IP")
			return
		}
		requestedIP = msg.Message.ClientIP
	}

	if selectedServer != nil && !serverIP.Equal(selectedServer) {
		fmt.Println("Server IP not equal, clearing client leases")
		pool.freeLeases(&clientID)
		return
	}

	if selectedServer == nil {
		fmt.Println("Client refreshing old lease")
	} else {
		fmt.Println("Accepting new IP")
	}

	// validate requested IP
	idx, err := pool.indexFromAddress(requestedIP)
	if err != nil {
		if selectedServer != nil {
			pool.sendNack(msg, sender, serverIP, "Invalid address")
		}
		return
	}
	lease, found := pool.Leases[idx]
	if !found {
		if selectedServer != nil {
			pool.sendNack(msg, sender, serverIP, "No lease found")
		}
		return
	}
	if !lease.ID.equals(&clientID) {
		if selectedServer != nil {
			pool.sendNack(msg, sender, serverIP, "Requested IP address is leased by different client")
		}
		return
	}

	lease.State = LeaseInUse
	lease.Expires = time.Now().Add(pool.Lifetime)

	// build ack
	ack := BuildBasicReply(&msg.Message, serverIP)
	ack.YourIP = lease.Address

	ack.Options[DHCPMessageTypeOptionCode] = &Uint8DHCPOption{
		Value: []uint8{
			uint8(DHCPAck),
		},
	}
	ack.Options[SubnetMaskOptionCode] = &IPDHCPOption{
		Value: []net.IP{
			net.IPv4(pool.Network.Mask[0], pool.Network.Mask[1], pool.Network.Mask[2], pool.Network.Mask[3]),
		},
	}
	ack.Options[RouterOptionCode] = &IPDHCPOption{
		Value: []net.IP{
			serverIP,
		},
	}
	ack.Options[DomainNameServerOptionCode] = &IPDHCPOption{
		Value: []net.IP{
			serverIP,
		},
	}
	ack.Options[IPAddressLeaseTimeOptionCode] = &DurationDHCPOption{
		Value: pool.Lifetime,
	}

	fmt.Println("Sending ACK")
	DebugDHCPMessage(&ack)

	sender <- DirectedDHCPMessage{
		Message:   ack,
		Interface: msg.Interface,
		Remote:    msg.Remote,
	}
}

func (pool *Pool) sendNack(msg *DirectedDHCPMessage, sender chan<- DirectedDHCPMessage, serverIP net.IP, reason string) {
	nak := BuildBasicReply(&msg.Message, serverIP)

	nak.Options[DHCPMessageTypeOptionCode] = &Uint8DHCPOption{
		Value: []uint8{
			uint8(DHCPNak),
		},
	}
	nak.Options[MessageOptionCode] = &StringDHCPOption{
		Value: reason,
	}

	fmt.Println("Sending NAK")
	DebugDHCPMessage(&nak)

	sender <- DirectedDHCPMessage{
		Message:   nak,
		Interface: msg.Interface,
		Remote:    msg.Remote,
	}
}

func (pool *Pool) handleDecline(msg *DirectedDHCPMessage, sender chan<- DirectedDHCPMessage) {
	// TODO:
}

func (pool *Pool) handleRelease(msg *DirectedDHCPMessage, sender chan<- DirectedDHCPMessage) {
	clientID := newClientIdentifier(&msg.Message)
	serverIP := pool.serverIP(msg.Interface)

	if msg.Message.ServerIP.Equal(serverIP) {
		pool.freeLeases(&clientID)
	}
}

func (pool *Pool) handleInform(msg *DirectedDHCPMessage, sender chan<- DirectedDHCPMessage) {
	// TODO:
}

func (pool *Pool) addressFromIndex(index uint32) net.IP {
	mask := (uint32(pool.Network.IP[0]) << 24) |
		(uint32(pool.Network.IP[1]) << 16) |
		(uint32(pool.Network.IP[2]) << 8) |
		uint32(pool.Network.IP[3])

	mask |= index + pool.Start

	return net.IPv4(byte(mask>>24&0xFF), byte(mask>>16&0xFF), byte(mask>>8&0xFF), byte(mask&0xFF))
}

func (pool *Pool) indexFromAddress(ip net.IP) (uint32, error) {
	mask := (uint32(pool.Network.IP[0]) << 24) |
		(uint32(pool.Network.IP[1]) << 16) |
		(uint32(pool.Network.IP[2]) << 8) |
		uint32(pool.Network.IP[3])

	ip4 := ip.To4()

	if ip4 == nil {
		return 0, errors.New("Invalid IPv4 address")
	}

	ipaddr := (uint32(ip4[0]) << 24) |
		(uint32(ip4[1]) << 16) |
		(uint32(ip4[2]) << 8) |
		uint32(ip4[3])

	// TODO: validation
	//network := ipaddr & mask
	idx := (ipaddr & ^mask) - pool.Start

	fmt.Println("Index from address:", idx)

	return idx, nil
}

func selectNumber(algo AddressSelectAlgorithm, indices []uint32) uint32 {
	switch algo {
	case Sequential:
		return indices[0]

	case Randomized:
		return indices[rand.Intn(len(indices))]
	}

	return 0
}

func (pool *Pool) freeIndices() []uint32 {
	result := make([]uint32, 0)

	for i := pool.Start; i <= pool.End; i++ {
		if _, exists := pool.Leases[i]; !exists {
			result = append(result, i)
		}
	}

	return result
}

func (pool *Pool) findClientLease(id *ClientIdentifier) (*Lease, bool) {
	for _, l := range pool.Leases {
		if l.ID.equals(id) {
			return l, true
		}
	}

	return nil, false
}

func (pool *Pool) freeLeases(id *ClientIdentifier) {
	for i, lease := range pool.Leases {
		if pool.Leases[i].ID.equals(id) {
			// removing items from map inside range is legal
			delete(pool.Leases, i)
			fmt.Println("Freeing ", lease.Address)
		}
	}
}

func (id *ClientIdentifier) equals(other *ClientIdentifier) bool {
	if len(id.ID) > 0 {
		return bytes.Equal(id.ID, other.ID)
	}

	return bytes.Equal(id.Mac, other.Mac)
}

func newClientIdentifier(msg *DHCPMessage) ClientIdentifier {
	return ClientIdentifier{
		Mac: msg.ClientHwAddr,
	}
}

func (pool *Pool) serverIP(iface *net.Interface) net.IP {
	addresses, _ := iface.Addrs()

	for _, addr := range addresses {
		var ip net.IP

		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}

		if ip4 := ip.To4(); ip4 != nil {
			return ip4
		}
	}

	// tbh we should just panic ..
	return net.IPv4(0, 0, 0, 0)
}
