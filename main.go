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
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		fmt.Println(packet.Dump())
		ipLayer, _ := ipLayer.(*layers.IPv4)
		ethernetLayer, _ := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		ipLayer.TOS = 1
		options := gopacket.SerializeOptions{ComputeChecksums: true}
		buffer := gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(buffer, options,
			ethernetLayer,
			ipLayer)
		outgoingPacket := buffer.Bytes()
		return outgoingPacket
	} else {
		return packet.Data()
	}
}
