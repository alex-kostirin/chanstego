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
		fmt.Println("PACKET IN:")
		fmt.Println(packet.Data())
		ipLayer, _ := ipLayer.(*layers.IPv4)
		fmt.Println("TOS BEFORE")
		fmt.Println(ipLayer.TOS)
		ipLayer.TOS = uint8(255)
		fmt.Println("TOS AFTER")
		fmt.Println(ipLayer.TOS)
		options := gopacket.SerializeOptions{ComputeChecksums: true}
		buffer := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buffer, options, ipLayer, gopacket.Payload(ipLayer.Payload))
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
