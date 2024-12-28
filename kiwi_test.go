package kiwi

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"net"
	"net/netip"
	"runtime"
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

func TestShutdown(t *testing.T) {
	listenUdp, err := net.ListenUDP("udp", nil)
	assert.NoError(t, err)

	c := &Client{
		Conn: listenUdp,
		Handler: func(b []byte, addr netip.AddrPort) {
			fmt.Printf("%s - %x\n", addr, b)
		},
	}

	assert.Equal(t, 2, runtime.NumGoroutine())

	c.Listen()

	assert.Equal(t, 3, runtime.NumGoroutine())

	assert.NoError(t, c.Shutdown())

	assert.Equal(t, 2, runtime.NumGoroutine())
}

func TestKiwi_Send(t *testing.T) {
	listenUdp, err := net.ListenUDP("udp", nil)
	assert.NoError(t, err)

	println("a")

	listenOtherUdp, err := net.ListenUDP("udp", nil)
	assert.NoError(t, err)

	println("b")

	c := &Client{
		Conn: listenUdp,
		Handler: func(b []byte, addr netip.AddrPort) {
			fmt.Printf("%s - %x\n", addr, b)
		},
	}
	c.Listen()

	println("c")

	go func() {
		var b [1024]byte
		n, addr, err := listenOtherUdp.ReadFromUDPAddrPort(b[:])
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s - %x\n", addr, b[:n])
	}()

	println("d")

	c.Send([]byte{0x54, 0xe5}, listenOtherUdp.LocalAddr().(*net.UDPAddr).AddrPort())

	println("e")

	<-time.After(5 * time.Second)
	println("f")
	assert.NoError(t, c.Shutdown())
}
