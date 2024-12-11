package kiwi

import (
	"crypto/rsa"
	"net"
	"sync/atomic"
	"time"
)

const cryptoTimeWeight = 30 * time.Second

type Client struct {
	Conn       *net.UDPConn
	Handler    Handler
	BufferSize int

	cryptoKey     *rsa.PrivateKey
	cryptoTimeout time.Time

	// client state
	running atomic.Bool
}

func (c *Client) Listen() {
	if c.running.Swap(true) {
		panic("Cannot start a single kiwi client twice")
	}
	go c.internalRunner()
}

func (c *Client) Shutdown() error {
	if !c.running.Swap(false) {
		panic("Kiwi client is not running")
	}
	return c.Conn.Close()
}

func (c *Client) internalRunner() {
	b := make([]byte, 4096)
	for {
		n, addr, err := c.Conn.ReadFromUDPAddrPort(b)
		if err != nil {
			continue
		}
		read := b[:n]
		// TODO(melon): process crypto sync
		c.Handler(read, addr)
	}
}
