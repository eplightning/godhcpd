package internal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

type DHCPOptionCode uint8
type DHCPOptions map[DHCPOptionCode]DHCPOption

const (
	PadOptionCode                    DHCPOptionCode = 0
	SubnetMaskOptionCode             DHCPOptionCode = 1
	TimeOffsetOptionCode             DHCPOptionCode = 2
	RouterOptionCode                 DHCPOptionCode = 3
	TimeServerOptionCode             DHCPOptionCode = 4
	NameServerOptionCode             DHCPOptionCode = 5
	DomainNameServerOptionCode       DHCPOptionCode = 6
	HostNameOptionCode               DHCPOptionCode = 12
	DomainNameOptionCode             DHCPOptionCode = 15
	IPForwardingEnableOptionCode     DHCPOptionCode = 19
	InterfaceMTUOptionCode           DHCPOptionCode = 26
	StaticRouteOptionCode            DHCPOptionCode = 33
	NTPServerOptionCode              DHCPOptionCode = 42
	RequestIPAddressOptionCode       DHCPOptionCode = 50
	IPAddressLeaseTimeOptionCode     DHCPOptionCode = 51
	OptionOverloadOptionCode         DHCPOptionCode = 52
	DHCPMessageTypeOptionCode        DHCPOptionCode = 53
	ServerIdentifierOptionCode       DHCPOptionCode = 54
	ParameterRequestListOptionCode   DHCPOptionCode = 55
	MessageOptionCode                DHCPOptionCode = 56
	MaximumDHCPMessageSizeOptionCode DHCPOptionCode = 57
	RenewalTimeValueOptionCode       DHCPOptionCode = 58
	RebindingTimeValueOptionCode     DHCPOptionCode = 59
	VendorClassIdentifierOptionCode  DHCPOptionCode = 60
	ClientIdentifierOptionCode       DHCPOptionCode = 61
	EndOptionCode                    DHCPOptionCode = 255
)

type DHCPOption interface {
	Encode() []byte
	Decode(data []byte) bool
	Data() interface{}
}

type IPDHCPOption struct {
	Value []net.IP
}

type Uint8DHCPOption struct {
	Value []uint8
}

type Uint16DHCPOption struct {
	Value []uint16
}

type StringDHCPOption struct {
	Value string
}

type DurationDHCPOption struct {
	Value time.Duration
}

func DecodeDHCPOptions(data []byte) (DHCPOptions, error) {
	output := make(DHCPOptions)

	size := len(data)

	for i := 0; i < len(data); i++ {
		code := DHCPOptionCode(data[i])

		if code == PadOptionCode {
			continue
		} else if code == EndOptionCode {
			return output, nil
		} else {
			i++
			length := int(data[i])

			if length < 0 || length > size-i-1 {
				return nil, errors.New("Invalid DHCP option length")
			}

			option, err := decodeOption(code, data[i+1:i+1+length])
			if err != nil {
				return nil, err
			}

			if option != nil {
				output[code] = option
			} else {
				// todo: warning about not consumed option
			}

			i = i + length
		}
	}

	return nil, errors.New("Options not terminated properly")
}

func decodeOption(code DHCPOptionCode, data []byte) (DHCPOption, error) {
	var opt DHCPOption

	switch code {
	// ip
	case SubnetMaskOptionCode, RouterOptionCode, TimeServerOptionCode, NameServerOptionCode,
		DomainNameServerOptionCode, StaticRouteOptionCode, NTPServerOptionCode, RequestIPAddressOptionCode,
		ServerIdentifierOptionCode:
		opt = &IPDHCPOption{}
	// duration
	case TimeOffsetOptionCode, IPAddressLeaseTimeOptionCode, RenewalTimeValueOptionCode, RebindingTimeValueOptionCode:
		opt = &DurationDHCPOption{}
	// string
	case HostNameOptionCode, DomainNameOptionCode, MessageOptionCode, VendorClassIdentifierOptionCode:
		opt = &StringDHCPOption{}
	case IPForwardingEnableOptionCode, OptionOverloadOptionCode, DHCPMessageTypeOptionCode, ParameterRequestListOptionCode,
		ClientIdentifierOptionCode:
		opt = &Uint8DHCPOption{}
	// uint16
	case InterfaceMTUOptionCode, MaximumDHCPMessageSizeOptionCode:
		opt = &Uint16DHCPOption{}
	default:
		return nil, nil
	}

	if opt.Decode(data) {
		return opt, nil
	}

	return nil, fmt.Errorf("Unable to parse option: 0x%X", code)
}

func (options DHCPOptions) Encode() ([]byte, error) {
	var buffer bytes.Buffer

	for code, opt := range options {
		if code == EndOptionCode || code == PadOptionCode {
			continue
		} else {
			buffer.WriteByte(byte(code))
			data := opt.Encode()

			if len(data) > 255 {
				return nil, errors.New("Option taking more than 255 bytes detected")
			}

			buffer.WriteByte(byte(len(data)))
			buffer.Write(data)
		}
	}

	buffer.WriteByte(byte(EndOptionCode))

	return buffer.Bytes(), nil
}

func (opt *IPDHCPOption) Encode() []byte {
	buffer := make([]byte, len(opt.Value)*4)

	index := 0

	for _, ip := range opt.Value {
		if ipv4 := ip.To4(); ipv4 != nil {
			copy(buffer[index*4:], ipv4[:4])
		} else {
			panic("IPv6?")
		}

		index++
	}

	return buffer
}

func (opt *IPDHCPOption) Data() interface{} {
	return opt.Value
}

func (opt *IPDHCPOption) Decode(data []byte) bool {
	if len(data)%4 != 0 {
		return false
	}

	count := len(data) / 4

	opt.Value = make([]net.IP, count)

	for i := 0; i < count; i++ {
		opt.Value[i] = net.IPv4(data[i*4], data[i*4+1], data[i*4+2], data[i*4+3])
	}

	return true
}

func (opt *Uint8DHCPOption) Encode() []byte {
	return opt.Value
}

func (opt *Uint8DHCPOption) Data() interface{} {
	return opt.Value
}

func (opt *Uint8DHCPOption) Decode(data []byte) bool {
	opt.Value = make([]uint8, len(data))
	copy(opt.Value, data)

	return true
}

func (opt *Uint16DHCPOption) Encode() []byte {
	buffer := new(bytes.Buffer)

	binary.Write(buffer, binary.BigEndian, opt.Value)

	return buffer.Bytes()
}

func (opt *Uint16DHCPOption) Decode(data []byte) bool {
	if len(data)%2 != 0 {
		return false
	}

	opt.Value = make([]uint16, len(data)/2)
	buffer := bytes.NewReader(data)

	return binary.Read(buffer, binary.BigEndian, &opt.Value) == nil
}

func (opt *Uint16DHCPOption) Data() interface{} {
	return opt.Value
}

func (opt *StringDHCPOption) Encode() []byte {
	return []byte(opt.Value)
}

func (opt *StringDHCPOption) Decode(data []byte) bool {
	buffer := make([]byte, len(data))
	copy(buffer, data)

	// wouldn't that make copy by itself anyway?
	opt.Value = string(buffer)

	return true
}

func (opt *StringDHCPOption) Data() interface{} {
	return opt.Value
}

func (opt *DurationDHCPOption) Encode() []byte {
	buffer := new(bytes.Buffer)

	binary.Write(buffer, binary.BigEndian, uint32(opt.Value/time.Second))

	return buffer.Bytes()
}

func (opt *DurationDHCPOption) Decode(data []byte) bool {
	if len(data) != 4 {
		return false
	}

	var four uint32

	if binary.Read(bytes.NewReader(data), binary.BigEndian, &four) != nil {
		return false
	}

	opt.Value = time.Duration(four) * time.Second

	return true
}

func (opt *DurationDHCPOption) Data() interface{} {
	return opt.Value
}
