package main

import (
	"fmt"
	"os"
	"github.com/alex-kostirin/ipstego/chanstego"
)

func main() {
	stegoConn, err := chanstego.NewIpTosStefoConn(0)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	data := make([]byte, 1)
	data[0] = 200
	n, err := stegoConn.Read(data)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(data)
	fmt.Println(n)
}
