package internal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

type BootpOperation uint8
type BootpFlag uint16
type DHCPType uint8
type BootpHwType uint8

const (
	BootRequest BootpOperation = 1
	BootReply   BootpOperation = 2
)

const (
	DHCPUnknown  DHCPType = 0
	DHCPDiscover DHCPType = 1
	DHCPOffer    DHCPType = 2
	DHCPRequest  DHCPType = 3
	DHCPDecline  DHCPType = 4
	DHCPAck      DHCPType = 5
	DHCPNak      DHCPType = 6
	DHCPRelease  DHCPType = 7
	DHCPInform   DHCPType = 8
)

const (
	BootpBroadcast BootpFlag = 0x8000
)

const (
	BootpEthernet BootpHwType = 1
)

const dhcpMagicCookie uint32 = 0x63825363
const bootpHeaderSize = 12 + 32 + 64 + 128

// BootpHeader is fixed part of message
type BootpHeader struct {
	BootpOperation
	HwAddrType    BootpHwType
	Hops          uint8
	TransactionID uint32
	Seconds       time.Duration
	Flags         BootpFlag
	ClientIP      net.IP
	YourIP        net.IP
	ServerIP      net.IP
	RelayAgentIP  net.IP
	ClientHwAddr  net.HardwareAddr
	ServerName    string
	FileName      string
}

type rawBootpHeader struct {
	Op            uint8
	HwAddrType    uint8
	HwAddrLength  uint8
	Hops          uint8
	TransactionID uint32
	Seconds       uint16
	Flags         uint16
	ClientIP      [4]byte
	YourIP        [4]byte
	ServerIP      [4]byte
	RelayAgentIP  [4]byte
	ClientHwAddr  [16]byte
	ServerName    [64]byte
	FileName      [128]byte
}

// DHCPMessage is entire DHCP message
type DHCPMessage struct {
	BootpHeader
	Options DHCPOptions
}

func ipToArray(ip net.IP) [4]byte {
	var arr [4]byte

	if ip2 := ip.To4(); ip2 != nil {
		copy(arr[:], ip2[:4])
	}

	return arr
}

func cstringToGo(bytes []byte) string {
	n := -1

	for i, b := range bytes {
		if b == 0 {
			break
		}
		n = i
	}

	return string(bytes[:n+1])
}

func (bootp *BootpHeader) raw() rawBootpHeader {
	raw := rawBootpHeader{
		Op:            uint8(bootp.BootpOperation),
		HwAddrType:    uint8(bootp.HwAddrType),
		HwAddrLength:  uint8(len(bootp.ClientHwAddr)),
		Hops:          bootp.Hops,
		TransactionID: bootp.TransactionID,
		Seconds:       uint16(bootp.Seconds / time.Second),
		Flags:         uint16(bootp.Flags),
		ClientIP:      ipToArray(bootp.ClientIP),
		YourIP:        ipToArray(bootp.YourIP),
		ServerIP:      ipToArray(bootp.ServerIP),
		RelayAgentIP:  ipToArray(bootp.RelayAgentIP),
	}

	var mac [16]byte
	var serverName [64]byte
	var fileName [128]byte
	copy(mac[:], bootp.ClientHwAddr[:raw.HwAddrLength])
	copy(serverName[:64], bootp.ServerName[:])
	copy(fileName[:128], bootp.FileName[:])

	raw.ClientHwAddr = mac
	raw.ServerName = serverName
	raw.FileName = fileName

	return raw
}

func (raw *rawBootpHeader) transform() (BootpHeader, error) {
	bootp := BootpHeader{
		BootpOperation: BootpOperation(raw.Op),
		HwAddrType:     BootpHwType(raw.HwAddrType),
		Hops:           raw.Hops,
		TransactionID:  raw.TransactionID,
		Seconds:        time.Duration(raw.Seconds) * time.Second,
		Flags:          BootpFlag(raw.Flags),
		ClientIP:       net.IPv4(raw.ClientIP[0], raw.ClientIP[1], raw.ClientIP[2], raw.ClientIP[3]),
		YourIP:         net.IPv4(raw.YourIP[0], raw.YourIP[1], raw.YourIP[2], raw.YourIP[3]),
		ServerIP:       net.IPv4(raw.ServerIP[0], raw.ServerIP[1], raw.ServerIP[2], raw.ServerIP[3]),
		RelayAgentIP:   net.IPv4(raw.RelayAgentIP[0], raw.RelayAgentIP[1], raw.RelayAgentIP[2], raw.RelayAgentIP[3]),
		ServerName:     cstringToGo(raw.ServerName[:]),
		FileName:       cstringToGo(raw.FileName[:]),
	}

	if raw.Op != uint8(BootRequest) && raw.Op != uint8(BootReply) {
		return bootp, errors.New("Invalid BootP operation")
	}

	hwLength := int(raw.HwAddrLength)

	if hwLength <= 0 || hwLength > 16 {
		return bootp, errors.New("Invalid MAC address length")
	}

	bootp.ClientHwAddr = make([]byte, hwLength)
	copy(bootp.ClientHwAddr, raw.ClientHwAddr[:hwLength])

	return bootp, nil
}

func UnmarshallDHCPMessage(msg []byte) (DHCPMessage, error) {
	var header rawBootpHeader
	var out DHCPMessage
	reader := bytes.NewReader(msg)

	// header
	if err := binary.Read(reader, binary.BigEndian, &header); err != nil {
		return out, err
	}

	// cookie
	var cookie uint32

	if err := binary.Read(reader, binary.BigEndian, &cookie); err != nil {
		return out, errors.New("Unable to read DHCP cookie value")
	}

	if cookie != dhcpMagicCookie {
		return out, errors.New("Invalid DHCP cookie value")
	}

	// options
	options, err := DecodeDHCPOptions(msg[bootpHeaderSize+4:])

	if err != nil {
		return out, err
	}

	if out.BootpHeader, err = header.transform(); err != nil {
		return out, err
	}

	out.Options = options

	return out, nil
}

func MarshallDHCPMessage(msg DHCPMessage) ([]byte, error) {
	header := msg.BootpHeader.raw()
	buffer := &bytes.Buffer{}

	// header
	if err := binary.Write(buffer, binary.BigEndian, header); err != nil {
		return nil, nil
	}

	// cookie
	if err := binary.Write(buffer, binary.BigEndian, dhcpMagicCookie); err != nil {
		return nil, nil
	}

	// options
	opt, err := msg.Options.Encode()

	if err != nil {
		return nil, nil
	}

	if _, err := buffer.Write(opt); err != nil {
		return nil, nil
	}

	return buffer.Bytes(), nil
}

func DebugDHCPMessage(msg *DHCPMessage) {
	fmt.Println("Nagłówek: ", msg.BootpHeader)

	for code, item := range msg.Options {
		fmt.Println("Opcja DHCP ", code, item)
	}
}

func (msg *DHCPMessage) Type() DHCPType {
	opt, found := msg.Options[DHCPMessageTypeOptionCode]

	t := opt.Data().([]uint8)[0]

	if !found || t > uint8(DHCPInform) || t == 0 {
		return DHCPUnknown
	}

	return DHCPType(t)
}

func (msg *DHCPMessage) RequestedIP() net.IP {
	opt, found := msg.Options[RequestIPAddressOptionCode]

	if !found {
		return nil
	}

	return opt.Data().([]net.IP)[0]
}

func (msg *DHCPMessage) ServerIdentifier() net.IP {
	opt, found := msg.Options[ServerIdentifierOptionCode]

	if !found {
		return nil
	}

	return opt.Data().([]net.IP)[0]
}

func BuildBasicReply(request *DHCPMessage, serverIP net.IP) DHCPMessage {
	header := BootpHeader{
		BootpOperation: BootReply,
		HwAddrType:     request.HwAddrType,
		Hops:           request.Hops,
		TransactionID:  request.TransactionID,
		Seconds:        request.Seconds,
		Flags:          BootpBroadcast,
		ServerIP:       serverIP,
		RelayAgentIP:   net.IPv4zero,
		ClientIP:       net.IPv4zero,
		YourIP:         net.IPv4zero,
		ClientHwAddr:   request.ClientHwAddr,
	}

	options := make(DHCPOptions)

	options[ServerIdentifierOptionCode] = &IPDHCPOption{
		Value: []net.IP{serverIP},
	}

	return DHCPMessage{
		BootpHeader: header,
		Options:     options,
	}
}
