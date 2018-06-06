package main

import (
	"fmt"
	"os"
	"gitlab.com/alex-kostirin/chanstego"
)

func main() {
	// Listen for incoming connections.
	l, err := chanstego.Listen("IP.TOS", 10, 20)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	// Close the listener when the application closes.
	defer l.Close()
	fmt.Println("Listening for IP.TOS connection")
	conn, err := l.Accept()
	if err != nil {
		fmt.Println("Error accepting: ", err.Error())
		os.Exit(1)
	}
	fmt.Println("Accepted stego connection on " + l.Addr().String())
	incomingData := make([]byte, 10)
	n, err := conn.Read(incomingData)
	if err != nil {
		fmt.Println("Error reading data: ", err.Error())
		os.Exit(1)
	}
	fmt.Printf("Read %d bytes", n)
	fmt.Println(incomingData)
	outgoingData := []byte{127, 56, 78, 90}
	n, err = conn.Write(outgoingData)
	if err != nil {
		fmt.Println("Error writing data: ", err.Error())
		os.Exit(1)
	}
	fmt.Printf("Wrote %d bytes", n)
	fmt.Println(outgoingData)
}
