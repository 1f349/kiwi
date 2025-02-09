package kiwi

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
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
	slices.Repeat([]byte{1, 2, 3, 4}, 25),
	slices.Repeat([]byte{1, 2, 3, 4}, 50),
	slices.Repeat([]byte{1, 2, 3, 4}, 100),
	slices.Repeat([]byte{1, 2, 3, 4}, 200),
	slices.Repeat([]byte{1, 2, 3, 4}, 300),
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
			assertSending := func(t *testing.T, err error) {
				assert.NoError(t, err)
			}
			if len(packet0) > 900 {
				assertSending = func(t *testing.T, err error) {
					t.Helper()
					assert.ErrorIs(t, err, ErrDataTooLong)
				}
			}

			listenUdp, err := net.ListenUDP("udp", nil)
			assert.NoError(t, err)

			listenOtherUdp, err := net.ListenUDP("udp", nil)
			assert.NoError(t, err)

			myPort := listenUdp.LocalAddr().(*net.UDPAddr).AddrPort().Port()
			otherPort := listenOtherUdp.LocalAddr().(*net.UDPAddr).AddrPort().Port()
			t.Log("myPort", myPort)
			t.Log("otherPort", otherPort)

			gotPacketOnA := new(atomic.Int32)
			gotPacketOnB := new(atomic.Int32)

			ca := &Client{
				Conn:       listenUdp,
				privateKey: must(GeneratePrivateKey()),
				Handler: func(b []byte, addr netip.AddrPort) {
					fmt.Printf("ca: %s - %d - %x\n", addr, len(b), b)
					for i, pb := range packetSlice {
						if bytes.Equal(b, pb) {
							gotPacketOnA.Or(1 << i)
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
							gotPacketOnB.Or(1 << i)
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

			err = ca.Send(packet0, netip.AddrPortFrom(netip.IPv6Loopback(), otherPort))
			assertSending(t, err)
			err = ca.Send(packet1, netip.AddrPortFrom(netip.IPv6Loopback(), otherPort))
			assertSending(t, err)

			err = cb.Send(packet0, netip.AddrPortFrom(netip.IPv6Loopback(), myPort))
			assertSending(t, err)
			err = cb.Send(packet1, netip.AddrPortFrom(netip.IPv6Loopback(), myPort))
			assertSending(t, err)

			<-time.After(hmacTimeCycle + 3*time.Second)

			err = ca.Send(packet2, netip.AddrPortFrom(netip.IPv6Loopback(), otherPort))
			assertSending(t, err)

			err = cb.Send(packet2, netip.AddrPortFrom(netip.IPv6Loopback(), myPort))
			assertSending(t, err)

			<-time.After(5 * time.Second)
			assert.NoError(t, ca.Shutdown())
			assert.NoError(t, cb.Shutdown())

			if len(packet0) > 900 {
				assert.Equal(t, int32(0), gotPacketOnA.Load())
				assert.Equal(t, int32(0), gotPacketOnB.Load())
			} else {
				assert.Equal(t, int32(0b111), gotPacketOnA.Load())
				assert.Equal(t, int32(0b111), gotPacketOnB.Load())
			}
		})
	}
}
