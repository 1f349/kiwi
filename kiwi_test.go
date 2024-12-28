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

func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

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

	listenOtherUdp, err := net.ListenUDP("udp", nil)
	assert.NoError(t, err)

	myPort := listenUdp.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	otherPort := listenOtherUdp.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	t.Log("myPort", myPort)
	t.Log("otherPort", otherPort)

	ca := &Client{
		Conn:       listenUdp,
		privateKey: must(GeneratePrivateKey()),
		Handler: func(b []byte, addr netip.AddrPort) {
			fmt.Printf("ca: %s - %x\n", addr, b)
		},
	}
	cb := &Client{
		Conn:       listenOtherUdp,
		privateKey: must(GeneratePrivateKey()),
		Handler: func(b []byte, addr netip.AddrPort) {
			fmt.Printf("cb: %s - %x\n", addr, b)
		},
	}

	ca.peers.Store(netip.IPv6Loopback(), cb.privateKey.PublicKey())
	cb.peers.Store(netip.IPv6Loopback(), ca.privateKey.PublicKey())

	ca.Listen()
	cb.Listen()

	ca.Send([]byte{0x54, 0xe5}, netip.AddrPortFrom(netip.IPv6Loopback(), otherPort))
	ca.Send([]byte{0x54, 0xe6}, netip.AddrPortFrom(netip.IPv6Loopback(), otherPort))

	time.Sleep(70 * time.Second)

	ca.Send([]byte{0x54, 0xe7}, netip.AddrPortFrom(netip.IPv6Loopback(), otherPort))

	<-time.After(5 * time.Second)
	assert.NoError(t, ca.Shutdown())
	assert.NoError(t, cb.Shutdown())
}
