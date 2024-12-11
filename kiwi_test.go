package kiwi

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestClient_Listen(t *testing.T) {
	listenUdp, err := net.ListenUDP("udp", nil)
	assert.NoError(t, err)

	c := &Client{
		Conn: listenUdp,
		Handler: func(b []byte, addr netip.AddrPort) {
			fmt.Printf("%s - %x\n", addr, b)
		},
	}
	c.Listen()

	go func() {
		dial, err := net.DialUDP("udp", nil, listenUdp.LocalAddr().(*net.UDPAddr))
		if err != nil {
			panic(err)
		}
		dial.Write([]byte{0x54, 0xe5})
		dial.Close()
	}()

	<-time.After(5 * time.Second)
	assert.NoError(t, c.Shutdown())
}
