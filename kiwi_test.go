package kiwi

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"net"
	"net/netip"
	"testing"
	"time"
)

func init() {
	hmacTimeCycle = 10 * time.Second
}

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

	c.Listen()

	select {
	case <-c.wrDone.C:
		assert.FailNow(t, "c.wrDone must not be closed after Listen()")
	default:
	}

	assert.NoError(t, c.Shutdown())

	select {
	case <-c.wrDone.C:
	default:
		assert.FailNow(t, "c.wrDone must be closed after Shutdown()")
	}
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
	ca.publicKey = ca.privateKey.PublicKey()

	cb := &Client{
		Conn:       listenOtherUdp,
		privateKey: must(GeneratePrivateKey()),
		Handler: func(b []byte, addr netip.AddrPort) {
			fmt.Printf("cb: %s - %x\n", addr, b)
		},
	}
	cb.publicKey = cb.privateKey.PublicKey()

	ca.peers.Store(netip.IPv6Loopback(), cb.privateKey.PublicKey())
	cb.peers.Store(netip.IPv6Loopback(), ca.privateKey.PublicKey())

	stripBool := func(k Key, b bool) Key { return k }

	fmt.Println("ca send -> cb", stripBool(ca.getSendingEncryptionKey(netip.MustParseAddrPort("[::1]:1234"))))
	fmt.Println("cb send -> ca", stripBool(cb.getSendingEncryptionKey(netip.MustParseAddrPort("[::1]:1234"))))
	fmt.Println("ca recv <- cb", stripBool(ca.getReceivingEncryptionKey(netip.MustParseAddrPort("[::1]:1234"), 0)))
	fmt.Println("cb recv <- ca", stripBool(cb.getReceivingEncryptionKey(netip.MustParseAddrPort("[::1]:1234"), 0)))

	ca.Listen()
	cb.Listen()

	ca.Send([]byte{0x54, 0xe5}, netip.AddrPortFrom(netip.IPv6Loopback(), otherPort))
	ca.Send([]byte{0x54, 0xe6}, netip.AddrPortFrom(netip.IPv6Loopback(), otherPort))

	cb.Send([]byte{0x5a, 0xe5}, netip.AddrPortFrom(netip.IPv6Loopback(), myPort))
	cb.Send([]byte{0x5a, 0xe6}, netip.AddrPortFrom(netip.IPv6Loopback(), myPort))

	time.Sleep(hmacTimeCycle + 5*time.Second)

	ca.Send([]byte{0x54, 0xe7}, netip.AddrPortFrom(netip.IPv6Loopback(), otherPort))

	cb.Send([]byte{0x5a, 0xe7}, netip.AddrPortFrom(netip.IPv6Loopback(), myPort))

	<-time.After(5 * time.Second)
	assert.NoError(t, ca.Shutdown())
	assert.NoError(t, cb.Shutdown())
}
