package chanstego

import (
	"github.com/alex-kostirin/go-netfilter-queue"
	"time"
	"io"
	"net"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type IpTosStegoConn struct {
	StegoConn
	NFQ          *netfilter.NFQueue
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func (c *IpTosStegoConn) Read(b []byte) (n int, err error) {
	packets := c.NFQ.GetPackets()
	for {
		if c.readTimeout != -1 {
			select {
			case <-time.After(c.readTimeout):
				{
					return 0, io.ErrNoProgress
				}
			case p := <-packets:
				if !c.IsValidPacket(p.Packet) {
					continue
				}
				data, packet := c.GetData(p.Packet)
				p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
				if len(b) < len(data) {
					return 0, io.ErrShortBuffer
				}
				copy(b, data)
				return len(b), nil

			}
		} else {
			select {
			case p := <-packets:
				if !c.IsValidPacket(p.Packet) {
					continue
				}
				data, packet := c.GetData(p.Packet)
				p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
				if len(b) < len(data) {
					return 0, io.ErrShortBuffer
				}
				copy(b, data)
				return len(b), nil
			}
		}
	}
}

func (c *IpTosStegoConn) Write(b []byte) (n int, err error) {
	packets := c.NFQ.GetPackets()
	if c.writeTimeout != -1 {
		for _, dataByte := range b {
			for {
				select {
				case <-time.After(c.readTimeout):
					{
						return 0, io.ErrNoProgress
					}
				case p := <-packets:
					if !c.IsValidPacket(p.Packet) {
						continue
					}
					data := []byte{dataByte}
					packet := c.InsertData(p.Packet, data)
					p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
					break

				}
			}
		}
		return len(b), nil
	} else {
		for _, dataByte := range b {
			for {
				select {
				case p := <-packets:
					if !c.IsValidPacket(p.Packet) {
						continue
					}
					data := []byte{dataByte}
					packet := c.InsertData(p.Packet, data)
					p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
					break
				}
			}
		}
		return len(b), nil
	}
}

func (c *IpTosStegoConn) Close() error {
	c.NFQ.Close()
	return nil
}

func (c *IpTosStegoConn) LocalAddr() net.Addr {
	return StegoAddr{StegoType: "IP.TOS"}
}

func (c *IpTosStegoConn) RemoteAddr() net.Addr {
	return StegoAddr{StegoType: "IP.TOS"}
}

func (c *IpTosStegoConn) SetDeadline(t time.Time) error {
	timeout := time.Until(t)
	c.readTimeout = timeout
	c.writeTimeout = timeout
	return nil
}

func (c *IpTosStegoConn) SetReadDeadline(t time.Time) error {
	timeout := time.Until(t)
	c.readTimeout = timeout
	return nil
}

func (c *IpTosStegoConn) SetWriteDeadline(t time.Time) error {
	timeout := time.Until(t)
	c.writeTimeout = timeout
	return nil
}

func (c *IpTosStegoConn) InsertData(packet gopacket.Packet, data []byte) []byte {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ipLayerData, _ := ipLayer.(*layers.IPv4)
	ipLayerData.TOS = uint8(data[0])
	options := gopacket.SerializeOptions{ComputeChecksums: true}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, ipLayerData, gopacket.Payload(ipLayerData.Payload))
	if err != nil {
		panic(err)
	}
	return buffer.Bytes()

}

func (c *IpTosStegoConn) GetData(packet gopacket.Packet) ([]byte, []byte) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ipLayerData, _ := ipLayer.(*layers.IPv4)
	dataByte := byte(ipLayerData.TOS)
	data := []byte{dataByte}
	ipLayerData.TOS = 0
	options := gopacket.SerializeOptions{ComputeChecksums: true}
	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options, ipLayerData, gopacket.Payload(ipLayerData.Payload))
	if err != nil {
		panic(err)
	}
	return data, buffer.Bytes()
}

func (c *IpTosStegoConn) IsValidPacket(packet gopacket.Packet) bool {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		return true
	}
	return false
}

func NewIpTosStefoConn(queueId uint16) (*IpTosStegoConn, error) {
	nfq, err := netfilter.NewNFQueue(queueId, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		return nil, err
	}
	return &IpTosStegoConn{NFQ: nfq, readTimeout: -1, writeTimeout: -1}, nil
}
