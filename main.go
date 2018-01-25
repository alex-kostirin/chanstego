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
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	n, err := stegoConn.Write(data)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(n)
}
