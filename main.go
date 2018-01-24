package main

import (
	"fmt"
	"os"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/alex-kostirin/go-netfilter-queue"
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
			packet := ChangePacket(p.Packet, 200)
			p.SetVerdictWithPacket(netfilter.NF_ACCEPT, packet)
		}
	}
}

func ChangePacket(packet gopacket.Packet, data uint8) []byte {
	outgoingPacket := packet.Data()
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ipLayer, _ := ipLayer.(*layers.IPv4)
		if ipLayer.TOS == 0 {
			ipLayer.TOS = data
			fmt.Println(ipLayer.TOS)
			options := gopacket.SerializeOptions{ComputeChecksums: true}
			buffer := gopacket.NewSerializeBuffer()
			err := gopacket.SerializeLayers(buffer, options, ipLayer, gopacket.Payload(ipLayer.Payload))
			if err != nil {
				panic(err)
			}
			outgoingPacket = buffer.Bytes()
		}
	}
	return outgoingPacket
}
