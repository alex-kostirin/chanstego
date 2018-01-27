package chanstego

import (
	"github.com/alex-kostirin/go-netfilter-queue"
	"time"
	"net"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"errors"
	"fmt"
)

type IpTosStegoConn struct {
	StegoConn
	inNfq           *netfilter.NFQueue
	outNfq          *netfilter.NFQueue
	readDeadline    time.Time
	writeDeadline   time.Time
	discoverTimeout time.Duration
	bindIp          net.IP
}

const (
	discoverCode       = byte(0xfe)
	acceptCode         = byte(0xff)
	okCode             = byte(0xff)
	startTransmitCode  = byte(0xfe)
	endTransmitCode    = byte(0xfe)
	invalidMessageMask = byte(0x01)
	invalidMessage     = byte(0x00)
	discoverTimeout    = 100
	maxReadBufLen      = 1024
	maxWriteBufLen     = 1024
)

func (c *IpTosStegoConn) Read(b []byte) (n int, err error) {
	packetsIn := c.inNfq.GetPackets()
	packetsOut := c.outNfq.GetPackets()
	var readBuf [maxReadBufLen * 8]byte
	bitsInBuf := 0

	const (
		stateWaitingTransmissionStart                = 1
		stateSendingTransmissionStartAcknowledgement = 2
		stateTransmissionStarted                     = 3
		stateSendingTransmissionEndAcknowledgement   = 4
	)
	transmissionState := stateWaitingTransmissionStart
	for {
		select {
		case p := <-packetsIn:
			if !c.isValidPacketAndAddress(p.Packet) || !(transmissionState == stateWaitingTransmissionStart || transmissionState == stateTransmissionStarted ) {
				p.SetVerdict(netfilter.NF_ACCEPT)
				continue
			}
			data, packet := c.getData(p.Packet)
			p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
			dataByte := data[0]
			if transmissionState == stateWaitingTransmissionStart {
				if dataByte == startTransmitCode {
					transmissionState = stateSendingTransmissionStartAcknowledgement
				}
			} else {
				if dataByte == endTransmitCode {
					transmissionState = stateSendingTransmissionEndAcknowledgement
					continue
				}
				if dataByte&invalidMessageMask == invalidMessage {
					continue
				}
				if bitsInBuf+7 > maxReadBufLen*8 {
					return 0, errors.New("can not read data - buffer is full")
				}
				for i := byte(7); i > 0; i-- {
					readBuf[bitsInBuf] = dataByte & (1 << i) >> i
					bitsInBuf++
				}
			}

		case p := <-packetsOut:
			if !c.isValidPacketAndAddress(p.Packet) || !(transmissionState == stateSendingTransmissionStartAcknowledgement || transmissionState == stateSendingTransmissionEndAcknowledgement ) {
				p.SetVerdict(netfilter.NF_ACCEPT)
				continue
			}
			if transmissionState == stateSendingTransmissionStartAcknowledgement {
				packet := c.insertData(p.Packet, []byte{okCode})
				p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
				transmissionState = stateTransmissionStarted
			} else {
				packet := c.insertData(p.Packet, []byte{okCode})
				p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
				transmissionState = stateTransmissionStarted
				nBytes := bitsInBuf / 8
				if bitsInBuf%8 != 0 {
					nBytes++
				}
				outDataBuf := make([]byte, nBytes)
				for j := 0; j < nBytes; j++ {
					bitOffset := j * 8
					dataByte := byte(0)
					for i := byte(0); i < 8; i++ {
						dataByte |= readBuf[7-int(i)+bitOffset] << i
					}
					outDataBuf[j] = dataByte
				}
				copy(b, outDataBuf)
				return nBytes, nil
			}
		}
	}
}

func (c *IpTosStegoConn) Write(b []byte) (n int, err error) {
	bitBufLen := (len(b) + len(b)/7) * 8
	if len(b)%7 != 0 {
		bitBufLen += 8
	}
	maxBitBufLen := (maxWriteBufLen + maxWriteBufLen/7) * 8
	if maxWriteBufLen%7 != 0 {
		maxBitBufLen += 8
	}
	if bitBufLen > maxBitBufLen {
		return 0, errors.New("can not write data - buffer is too small")
	}
	var offsetBuf [7]byte
	offsetBufIndex := 0
	bitBuf := make([]byte, bitBufLen)
	bitBufIndex := 0
	byteBufLen := bitBufLen / 8
	byteBuf := make([]byte, byteBufLen)
	for _, dataByte := range b {
		offsetBufIndex = 0
		for i := 7; i >= 0; i-- {
			bit := dataByte & (1 << byte(i)) >> byte(i)
			if (bitBufIndex+1)%8 != 0 {
				bitBuf[bitBufIndex] = bit
				bitBufIndex++
			} else {
				offsetBuf[offsetBufIndex] = bit
				offsetBufIndex++
			}
		}
		bitBuf[bitBufIndex] = byte(1)
		bitBufIndex++
		for i := 0; i < offsetBufIndex; i++ {
			bitBuf[bitBufIndex] = offsetBuf[i]
			bitBufIndex++
		}
		if (bitBufIndex+1)%8 == 0 {
			bitBuf[bitBufIndex] = byte(1)
			bitBufIndex++
		}
	}
	bitBuf[bitBufLen-1] = byte(1)
	for j := 0; j < byteBufLen; j++ {
		bitOffset := j * 8
		dataByte := byte(0)
		for i := byte(0); i < 8; i++ {
			dataByte |= bitBuf[7-int(i)+bitOffset] << i
		}
		byteBuf[j] = dataByte
	}
	packetsIn := c.inNfq.GetPackets()
	packetsOut := c.outNfq.GetPackets()
	byteBufIndex := 0

	const (
		stateSendingTransmissionStart         = 1
		stateTransmissionStarted              = 2
		stateSendingTransmissionEnd           = 3
		waitingTransmissionEndAcknowledgement = 4
	)
	transmissionState := stateSendingTransmissionStart
	for {
		select {
		case p := <-packetsIn:
			if !c.isValidPacketAndAddress(p.Packet) || !(transmissionState == stateSendingTransmissionStart || transmissionState == waitingTransmissionEndAcknowledgement ) {
				p.SetVerdict(netfilter.NF_ACCEPT)
				continue
			}
			data, packet := c.getData(p.Packet)
			p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
			dataByte := data[0]
			if transmissionState == stateSendingTransmissionStart {
				if dataByte == okCode {
					transmissionState = stateTransmissionStarted
					continue
				}
			} else {
				if dataByte == okCode {
					return len(b), nil
				}
			}
		case p := <-packetsOut:
			if !c.isValidPacketAndAddress(p.Packet) || transmissionState == waitingTransmissionEndAcknowledgement {
				p.SetVerdict(netfilter.NF_ACCEPT)
				continue
			}
			if transmissionState == stateSendingTransmissionStart {
				packet := c.insertData(p.Packet, []byte{startTransmitCode})
				p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
				continue
			}
			if transmissionState == stateTransmissionStarted {
				packet := c.insertData(p.Packet, []byte{byteBuf[byteBufIndex]})
				p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
				byteBufIndex++
				if byteBufIndex == byteBufLen {
					transmissionState = stateSendingTransmissionEnd
				}
				continue
			}
			if transmissionState == stateSendingTransmissionEnd {
				packet := c.insertData(p.Packet, []byte{endTransmitCode})
				p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
				transmissionState = waitingTransmissionEndAcknowledgement
				continue
			}
		}
	}
}

func (c *IpTosStegoConn) Close() error {
	c.inNfq.Close()
	c.outNfq.Close()
	return nil
}

func (c *IpTosStegoConn) LocalAddr() net.Addr {
	return &StegoAddr{StegoType: "IP.TOS"}
}

func (c *IpTosStegoConn) RemoteAddr() net.Addr {
	return &StegoAddr{StegoType: "IP.TOS"}
}

func (c *IpTosStegoConn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

func (c *IpTosStegoConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *IpTosStegoConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}

func (c *IpTosStegoConn) insertData(packet gopacket.Packet, data []byte) []byte {
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

func (c *IpTosStegoConn) getData(packet gopacket.Packet) ([]byte, []byte) {
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

func (c *IpTosStegoConn) isValidPacket(packet gopacket.Packet) bool {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		return true
	}
	return false
}

func (c *IpTosStegoConn) isValidPacketAndAddress(packet gopacket.Packet) bool {
	if c.isValidPacket(packet) {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		ipLayerData, _ := ipLayer.(*layers.IPv4)
		if ipLayerData.SrcIP.Equal(c.bindIp) {
			return true
		}
	}
	return false
}

func (c *IpTosStegoConn) Discover() error {
	packetsIn := c.inNfq.GetPackets()
	packetsOut := c.outNfq.GetPackets()
	const (
		stateSendingDiscover = 1
		stateSendingOk       = 3
	)
	handshakeState := stateSendingDiscover
	for {
		select {
		case <-time.After(c.discoverTimeout):
			{
				return errors.New(fmt.Sprintf("Can not discover after %d seconds", c.discoverTimeout))
			}
		case p := <-packetsIn:
			if !c.isValidPacket(p.Packet) || handshakeState == stateSendingOk {
				p.SetVerdict(netfilter.NF_ACCEPT)
				continue
			}
			data, packet := c.getData(p.Packet)
			p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
			if data[0] == acceptCode {
				c.setBindIp(p.Packet)
				handshakeState = stateSendingOk
			}
		case p := <-packetsOut:
			if !c.isValidPacket(p.Packet) {
				p.SetVerdict(netfilter.NF_ACCEPT)
				continue
			}
			if handshakeState == stateSendingDiscover {
				packet := c.insertData(p.Packet, []byte{discoverCode})
				p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
			} else {
				if !c.isValidPacketAndAddress(p.Packet) {
					p.SetVerdict(netfilter.NF_ACCEPT)
					continue
				}
				packet := c.insertData(p.Packet, []byte{okCode})
				p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
				return nil
			}
		}
	}
}

func (c *IpTosStegoConn) Accept() error {
	packetsIn := c.inNfq.GetPackets()
	packetsOut := c.outNfq.GetPackets()
	const (
		stateWaitingDiscover   = 1
		stateSendingAcceptance = 2
		stateWaitingOk         = 3
	)
	handshakeState := stateWaitingDiscover
	for {
		select {
		case <-time.After(c.discoverTimeout):
			{
				return errors.New(fmt.Sprintf("Can not accept connection after %d seconds", c.discoverTimeout))
			}
		case p := <-packetsIn:
			if !c.isValidPacket(p.Packet) || handshakeState == stateSendingAcceptance {
				p.SetVerdict(netfilter.NF_ACCEPT)
				continue
			}
			data, packet := c.getData(p.Packet)
			p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
			if handshakeState == stateWaitingDiscover {
				if data[0] == discoverCode {
					c.setBindIp(p.Packet)
					handshakeState = stateSendingAcceptance
				}
			} else {
				if data[0] == okCode {
					if c.isValidPacketAndAddress(p.Packet) {
						return nil
					}
				}
			}
		case p := <-packetsOut:
			if !c.isValidPacketAndAddress(p.Packet) || handshakeState != stateSendingAcceptance {
				p.SetVerdict(netfilter.NF_ACCEPT)
				continue
			}
			packet := c.insertData(p.Packet, []byte{acceptCode})
			p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
			handshakeState = stateWaitingOk
		}
	}
}

func (c *IpTosStegoConn) setBindIp(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ipLayerData, _ := ipLayer.(*layers.IPv4)
	c.bindIp = ipLayerData.SrcIP
}

func (c *IpTosStegoConn) GetBindIp() net.IP {
	return c.bindIp
}

func NewIpTosStegoConn(inQueueId uint16, outQueueId uint16) (*IpTosStegoConn, error) {
	nfqIn, err := netfilter.NewNFQueue(inQueueId, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		return nil, err
	}
	nfqOut, err := netfilter.NewNFQueue(outQueueId, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		return nil, err
	}
	return &IpTosStegoConn{inNfq: nfqIn, outNfq: nfqOut, readDeadline: time.Now(), writeDeadline: time.Now(), discoverTimeout: time.Second * discoverTimeout}, nil
}

type IpTosStegoListener struct {
	StegoListener
	inQueueId uint16
	outQueueId uint16
	conn StegoConn
}

func (l *IpTosStegoListener) Accept() (net.Conn, error)  {
	stegoConn, err := NewIpTosStegoConn(l.inQueueId, l.outQueueId)
	if err != nil {
		return nil, err
	}
	err = stegoConn.Accept()
	if err != nil {
		return nil, err
	}
	l.conn = stegoConn
	return stegoConn, nil
}

func (l *IpTosStegoListener) Close()  error  {
	err := l.conn.Close()
	if err != nil {
		return err
	}
	return nil
}

func (l *IpTosStegoListener) Addr()  net.Addr {
	return &StegoAddr{StegoType: "IP.TOS"}
}

func NewIpTosStegoListener(inQueueId uint16, outQueueId uint16) StegoListener {
	return &IpTosStegoListener{inQueueId:inQueueId, outQueueId:outQueueId}
}