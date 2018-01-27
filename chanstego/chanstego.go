package chanstego

import (
	"net"
	"errors"
	"fmt"
)

type StegoConn interface {
	net.Conn
	Discover() error
	Accept() error
	GetBindIp() net.IP
}

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


