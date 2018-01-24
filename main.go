package main

import (
	"fmt"
	"os"
	"github.com/google/gopacket"
	"github.com/alex-kostirin/go-netfilter-queue"
	"github.com/google/gopacket/layers"
)

func main() {
	var err error

	nfq, err := netfilter.NewNFQueue(0, 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer nfq.Close()
	packets := nfq.GetPackets()

	for true {
		select {
		case p := <-packets:
			packet := ChangePacket(p.Packet)
			p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
		}
	}
}

func ChangePacket(packet gopacket.Packet) []byte {
	if ipLayer, tcpLayer := packet.Layer(layers.LayerTypeIPv4), packet.Layer(layers.LayerTypeTCP); ipLayer != nil && tcpLayer != nil {
		fmt.Println("PACKET IN:")
		fmt.Println(packet.Data())
		ipLayer, _ := ipLayer.(*layers.IPv4)
		tcpLayer, _ := tcpLayer.(*layers.TCP)
		//ipLayer.Length = ipLayer.Length - 10
		timeStampOption := layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: []byte{2, 3, 5, 7, 11, 13, 12, 4}}
		nopOption := layers.TCPOption{OptionType: layers.TCPOptionKindNop, OptionLength:1}
		hasTcpTimestampOption := false
		for _, option := range tcpLayer.Options {
			if option.OptionType == layers.TCPOptionKindTimestamps {
				hasTcpTimestampOption = true
				break
			}
		}
		if !hasTcpTimestampOption && tcpLayer.DataOffset <= 12 {
			tcpOptions := make([]layers.TCPOption, len(tcpLayer.Options) + 3)
			for i, option := range tcpLayer.Options {
				tcpOptions[i] = option
			}
			tcpOptions[len(tcpLayer.Options)] = timeStampOption
			tcpOptions[len(tcpLayer.Options) + 1] = nopOption
			tcpOptions[len(tcpLayer.Options) + 2] = nopOption
			tcpLayer.Options = tcpOptions
			tcpLayer.DataOffset += 3
		}
		tcpLayer.SetNetworkLayerForChecksum(ipLayer)
		options := gopacket.SerializeOptions{ComputeChecksums: true}
		buffer := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buffer, options, ipLayer, tcpLayer, gopacket.Payload(tcpLayer.Payload))
		if err != nil {
			panic(err)
		}
		outgoingPacket := buffer.Bytes()
		fmt.Println("PACKET OUT")
		fmt.Println(outgoingPacket)
		return outgoingPacket
	} else {
		return packet.Data()
	}
}
