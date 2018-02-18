package main

import (
	"fmt"
	"os"
	"github.com/alex-kostirin/ipstego/chanstego"
)

func main() {

	// connect to this socket
	conn, err := chanstego.Dial("IP.TOS", 10, 20)
	if err != nil {
		fmt.Println("Error dialing:", err.Error())
		os.Exit(1)
	}
	fmt.Println("Dialed stego connection on " + conn.LocalAddr().String())
	outgoingData := []byte{34, 80, 2, 50}
	n, err := conn.Write(outgoingData)
	if err != nil {
		fmt.Println("Error writing data: ", err.Error())
		os.Exit(1)
	}
	fmt.Printf("Wrote %d bytes", n)
	fmt.Println(outgoingData)

	incomingData := make([]byte, 10)
	n, err = conn.Read(incomingData)
	if err != nil {
		fmt.Println("Error reading data: ", err.Error())
		os.Exit(1)
	}
	fmt.Printf("Read %d bytes", n)
	fmt.Println(incomingData)

}
