package chanstego

import (
	"net"
	"errors"
	"fmt"
)
// StegoConn interface is common interface for channel steganography connection.
// Implements net.Conn interface.
type StegoConn interface {
	net.Conn
	// Discover another endpoint of channel steganography connection
	Discover() error
	// Accepts discovering channel steganography connection
	Accept() error
	// Returns ip address of binded endpoint of channel steganography connection
	GetBindIp() net.IP
}

// StegoAddr struct implements net.Addr interface for stego connection
type StegoAddr struct {
	net.Addr
	StegoType string
}

func (a *StegoAddr) Network() string {
	return "chanstego"
}

func (a *StegoAddr) String() string {
	return a.StegoType
}

type StegoListener interface {
	net.Listener
}

// Dial connects to netfilter queues for ingoing and outgoing packets
// and returns new channel steganography connection.
//
// Known stego type is only "IP.TOS".
//
// You can compare usage as Dial function in net package
//
// Example:
//	Dial("IP.TOS", 10, 20)
func Dial(stegoType string, inQueueId uint16, outQueueId uint16) (StegoConn, error) {
	if stegoType == "IP.TOS" {
		stegoConn, err := NewIpTosStegoConn(inQueueId, outQueueId)
		if err != nil {
			stegoConn.Close()
			return nil, err
		}
		err = stegoConn.Discover()
		if err != nil {
			return nil, err
		}
		return stegoConn, nil
	} else {
		return nil, errors.New(fmt.Sprintf("%s stego type is not supported", stegoType))
	}
}

func Listen(stegoType string, inQueueId uint16, outQueueId uint16) (StegoListener, error) {
	if stegoType == "IP.TOS" {
		stegoListener := NewIpTosStegoListener(inQueueId, outQueueId)
		return stegoListener, nil
	} else {
		return nil, errors.New(fmt.Sprintf("%s stego type is not supported", stegoType))
	}
}


