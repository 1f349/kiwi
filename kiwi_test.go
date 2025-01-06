package kiwi

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"net"
	"net/netip"
	"slices"
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

var examplePackets = [][]byte{
	{0x54, 0xe5},
	slices.Repeat([]byte{1, 2, 3, 4}, 500),
}

func TestKiwi_Send(t *testing.T) {
	for _, packet0 := range examplePackets {
		lastIndex := len(packet0) - 1
		packet1 := slices.Clone(packet0)
		packet1[lastIndex]++
		packet2 := slices.Clone(packet0)
		packet2[lastIndex] += 2

		packetSlice := [][]byte{
			packet0,
			packet1,
			packet2,
		}

		t.Run(fmt.Sprintf("packet size %d", len(packet0)), func(t *testing.T) {
			listenUdp, err := net.ListenUDP("udp", nil)
			assert.NoError(t, err)

			listenOtherUdp, err := net.ListenUDP("udp", nil)
			assert.NoError(t, err)

			myPort := listenUdp.LocalAddr().(*net.UDPAddr).AddrPort().Port()
			otherPort := listenOtherUdp.LocalAddr().(*net.UDPAddr).AddrPort().Port()
			t.Log("myPort", myPort)
			t.Log("otherPort", otherPort)

			gotPacketOnA := 0b000
			gotPacketOnB := 0b000

			ca := &Client{
				Conn:       listenUdp,
				privateKey: must(GeneratePrivateKey()),
				Handler: func(b []byte, addr netip.AddrPort) {
					fmt.Printf("ca: %s - %d - %x\n", addr, len(b), b)
					for i, pb := range packetSlice {
						if bytes.Equal(b, pb) {
							gotPacketOnA |= 1 << i
							fmt.Println("counted")
							break
						}
					}
				},
			}
			ca.publicKey = ca.privateKey.PublicKey()

			cb := &Client{
				Conn:       listenOtherUdp,
				privateKey: must(GeneratePrivateKey()),
				Handler: func(b []byte, addr netip.AddrPort) {
					fmt.Printf("cb: %s - %d - %x\n", addr, len(b), b)
					for i, pb := range packetSlice {
						if bytes.Equal(b, pb) {
							gotPacketOnB |= 1 << i
							fmt.Println("counted")
							break
						}
					}
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

			ca.Send(packet0, netip.AddrPortFrom(netip.IPv6Loopback(), otherPort))
			ca.Send(packet1, netip.AddrPortFrom(netip.IPv6Loopback(), otherPort))

			cb.Send(packet0, netip.AddrPortFrom(netip.IPv6Loopback(), myPort))
			cb.Send(packet1, netip.AddrPortFrom(netip.IPv6Loopback(), myPort))

			<-time.After(hmacTimeCycle + 3*time.Second)

			ca.Send(packet2, netip.AddrPortFrom(netip.IPv6Loopback(), otherPort))

			cb.Send(packet2, netip.AddrPortFrom(netip.IPv6Loopback(), myPort))

			<-time.After(5 * time.Second)
			assert.NoError(t, ca.Shutdown())
			assert.NoError(t, cb.Shutdown())

			assert.Equal(t, 0b111, gotPacketOnA)
			assert.Equal(t, 0b111, gotPacketOnB)
		})
	}
}
