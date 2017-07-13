package internal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"syscall"
)

func EnablePktInfo(udp *net.UDPConn) error {
	file, err := udp.File()
	if err != nil {
		return err
	}

	err = syscall.SetsockoptInt(int(file.Fd()), syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)
	return err
}

func ReadUDPWithPktInfo(conn *net.UDPConn, b []byte) (int, int, *net.UDPAddr, syscall.Inet4Pktinfo, error) {
	var pktInfo syscall.Inet4Pktinfo

	oob := make([]byte, 1024)

	n, _, flags, addr, err := conn.ReadMsgUDP(b, oob)
	if err != nil {
		return n, flags, addr, pktInfo, err
	}

	oobBuffer := bytes.NewReader(oob)

	cmsg := &syscall.Cmsghdr{}

	if err = binary.Read(oobBuffer, binary.LittleEndian, cmsg); err != nil {
		return n, flags, addr, pktInfo, err
	}

	if cmsg.Level == syscall.IPPROTO_IP && cmsg.Type == syscall.IP_PKTINFO {
		if err = binary.Read(oobBuffer, binary.LittleEndian, &pktInfo); err != nil {
			return n, flags, addr, pktInfo, err
		}
	} else {
		// TODO: check all cmsg?
		return n, flags, addr, pktInfo, errors.New("No PKTInfo found ?")
	}

	return n, flags, addr, pktInfo, nil
}

func WriteUDPWithPktInfo(conn *net.UDPConn, b []byte, addr *net.UDPAddr, pktInfo *syscall.Inet4Pktinfo) (int, error) {
	var dataWriter bytes.Buffer

	// creating extra data
	msgOob := &syscall.Cmsghdr{
		Len:   28,
		Level: syscall.IPPROTO_IP,
		Type:  syscall.IP_PKTINFO,
	}

	if err := binary.Write(&dataWriter, binary.LittleEndian, msgOob); err != nil {
		return 0, err
	}
	if err := binary.Write(&dataWriter, binary.LittleEndian, pktInfo); err != nil {
		return 0, err
	}

	n, _, err := conn.WriteMsgUDP(b, dataWriter.Bytes(), addr)
	return n, err
}

func WriteUDPWithInterface(conn *net.UDPConn, b []byte, addr *net.UDPAddr, iface int32) (int, error) {
	return WriteUDPWithPktInfo(conn, b, addr, &syscall.Inet4Pktinfo{
		Ifindex: iface,
	})
}
