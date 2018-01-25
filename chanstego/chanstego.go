package chanstego

import (
	"net"
	"github.com/google/gopacket"
)

type StegoConn interface {
	net.Conn
	InsertData(packet gopacket.Packet, data []byte) []byte
	GetData(packet gopacket.Packet) ([]byte, []byte)
	IsValidPacket(packet gopacket.Packet) bool
}

type StegoAddr struct {
	net.Addr
	StegoType string
}

func (a *StegoAddr) Network() string {
	return "chanstego"
}

func (a *StegoAddr) String() string {
	return a.StegoType
}


