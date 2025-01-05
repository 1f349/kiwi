package kiwi

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/1f349/cache"
	"github.com/1f349/kiwi/internal/donechan"
	"github.com/1f349/syncmap"
	"golang.org/x/crypto/chacha20poly1305"
	"hash/crc32"
	"math"
	mathrand "math/rand"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const nonceSize = chacha20poly1305.NonceSizeX

type Handler func(b []byte, addr netip.AddrPort)

type Client struct {
	Conn       *net.UDPConn
	Handler    Handler
	BufferSize int

	privateKey Key
	publicKey  Key

	cryptoTimeout time.Time

	remoteState syncmap.Map[netip.AddrPort, *remoteStateItem]

	peers syncmap.Map[netip.Addr, Key]

	syncingHello syncmap.Map[netip.AddrPort, chan struct{}]

	remoteLastHello *cache.Cache[netip.AddrPort, time.Time]

	// client state
	running atomic.Bool

	// wg is the wait group for internal goroutines
	wg sync.WaitGroup

	// wrReady closes when internalWriter can send user data
	wrReady chan struct{}

	// wrDone is the done channel for internalWriter
	wrDone *donechan.DoneChan
}

func (c *Client) initClient() {
	if c.remoteLastHello == nil {
		c.remoteLastHello = cache.New[netip.AddrPort, time.Time]()
	}
}

type remoteStateItem struct {
	mu sync.RWMutex

	seq uint32

	// resend contains an array of the previous 20 packets to send
	resend *cache.Cache[uint32, []byte]

	// lastPing contains the last time a ping was sent to the remote connection
	lastPing time.Time
	// lastPong contains the last time a pong was received from the remote connection
	lastPong time.Time
	// lastRoundTrip contains the duration for the last full ping<->pong round trip
	lastRoundTrip time.Duration
}

func newRemoteStateItem() remoteStateItem {
	return remoteStateItem{
		resend: cache.New[uint32, []byte](),
	}
}

func (c *Client) Listen() {
	c.initClient()
	if c.running.Swap(true) {
		panic("Cannot start a single kiwi client twice")
	}
	if c.wrDone != nil {
		c.wrDone.Close()
	}
	c.wrDone = donechan.NewDoneChan()

	c.wg.Add(1)
	go c.internalReader()
}

func (c *Client) Shutdown() error {
	if !c.running.Swap(false) {
		panic("Kiwi client is not running")
	}
	err := c.Conn.Close()
	c.wg.Wait()
	return err
}

func (c *Client) getGenericLockedRemoteState(addr netip.AddrPort, lock func(item *remoteStateItem)) *remoteStateItem {
	state, loaded := c.remoteState.Load(addr)
	if !loaded {
		// try to store a new remote state
		newState := newRemoteStateItem()
		lock(&newState)
		state, loaded = c.remoteState.LoadOrStore(addr, &newState)

		// if the new state is stored then create a sequence number
		if !loaded {
			state.seq = mathrand.Uint32()
		}
	}

	// lock all loaded states
	// this will ignore the stored newState above
	if loaded {
		lock(state)
	}

	return state
}

// getLockedRemoteState safely find *remoteStateItem for a given AddrPort and
// returns with the mu.Lock() set
func (c *Client) getLockedRemoteState(addr netip.AddrPort) *remoteStateItem {
	return c.getGenericLockedRemoteState(addr, func(item *remoteStateItem) {
		item.mu.Lock()
	})
}

func (c *Client) getReadLockedRemoteState(addr netip.AddrPort) *remoteStateItem {
	return c.getGenericLockedRemoteState(addr, func(item *remoteStateItem) {
		item.mu.RLock()
	})
}

func (c *Client) Send(b []byte, addr netip.AddrPort) {
	c.internalHello(addr)
	c.sendEncryptedPacket(packetKindWholeData, b, addr)
}

func (c *Client) sendPacket(kind packetKind, flag uint8, data []byte, addr netip.AddrPort) {
	state := c.getLockedRemoteState(addr)
	seq := state.seq
	state.seq++
	state.mu.Unlock()
	b := encode(kind, seq, data)
	seq &= 0xf_ff_ff
	seq |= uint32(flag) << (32 - 4)
	state.resend.Set(seq, b, time.Now().Add(1*time.Minute))
	_, _ = c.Conn.WriteToUDPAddrPort(b, addr)
}

func (c *Client) sendEncryptedPacket(kind packetKind, data []byte, addr netip.AddrPort) {
	sharedKey, ok := c.getSendingEncryptionKey(addr)
	if !ok {
		return
	}
	cha, err := chacha20poly1305.NewX(sharedKey[:])
	if err != nil {
		return
	}

	packLen := nonceSize + chacha20poly1305.Overhead + len(data)
	iv := make([]byte, nonceSize, packLen)
	_, err = rand.Read(iv)
	if err != nil {
		return
	}

	// use the upper 4 bits of seq for the encryption flag
	encFlag := uint8(time.Now().UTC().Minute() % 10)

	pack := cha.Seal(iv, iv, data, []byte("kiwi"))
	c.sendPacket(kind, encFlag, pack, addr)
}

func (c *Client) getSendingEncryptionKey(addr netip.AddrPort) (Key, bool) {
	key, loaded := c.peers.Load(addr.Addr())
	if !loaded {
		return [KeyLen]byte{}, false
	}
	return c.getGenericEncryptionKey(addr, 0, key)
}

func (c *Client) getReceivingEncryptionKey(addr netip.AddrPort, flag uint8) (Key, bool) {
	return c.getGenericEncryptionKey(addr, flag, c.publicKey)
}

func (c *Client) getGenericEncryptionKey(addr netip.AddrPort, flag uint8, publicKey Key) (Key, bool) {
	peerPubKey, ok := c.peers.Load(addr.Addr())
	if !ok {
		return [KeyLen]byte{}, false
	}
	peerSharedKey, err := c.privateKey.SharedKey(peerPubKey)
	if err != nil {
		return [KeyLen]byte{}, false
	}
	n := time.Now().UTC()
	m := n.Minute() % 10
	if uint8(m) == flag-1 {
		n.Add(-time.Minute)
	}
	if uint8(m) == flag+1 {
		n.Add(time.Minute)
	}
	peerMacKey := hmacGenerateSharedKey(peerSharedKey, n, publicKey)
	return peerMacKey, true
}

func (c *Client) internalReader() {
	defer c.wg.Done()
	for {
		b := make([]byte, 4096)
		n, addr, err := c.Conn.ReadFromUDPAddrPort(b)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}

		go c.handlePacket(b[:n], addr)
	}
}

func (c *Client) internalHello(addr netip.AddrPort) {
	_, active := c.remoteLastHello.Get(addr)
	if active {
		return
	}

	ch := make(chan struct{})
	actual, loaded := c.syncingHello.LoadOrStore(addr, ch)
	if loaded {
		<-actual
		return
	}

	key, err := GenerateKey()
	if err != nil {
		return
	}
	const kiwiLen = 4
	var b [kiwiLen + crc32.Size + KeyLen]byte
	copy(b[:kiwiLen], "kiwi")
	copy(b[kiwiLen+crc32.Size:], key[:])
	checksum := crc32.ChecksumIEEE(b[:])
	binary.LittleEndian.PutUint32(b[kiwiLen:kiwiLen+crc32.Size], checksum)
	c.sendEncryptedPacket(packetKindHello, b[:], addr)

	<-actual
}

func (c *Client) ping(addr netip.AddrPort) {
	state := c.getLockedRemoteState(addr)
	state.lastPing = time.Now()
	state.mu.Unlock()
}

func (c *Client) handlePacket(b []byte, addr netip.AddrPort) {
	kind, seq, data, err := decode(b)
	if err != nil {
		return
	}

	// use the upper 4 bits of seq for the encryption flag
	encFlag := uint8(seq >> (32 - 4))
	seq &= math.MaxUint32 >> 4

	_ = seq

	// handle packet types
	switch kind {
	case packetKindHello:
		data = c.readEncryptedPacket(data, encFlag, addr)
		if data == nil {
			return
		}
		c.sendEncryptedPacket(packetKindHelloVerify, data, addr)
	case packetKindHelloVerify:
		data = c.readEncryptedPacket(data, 0, addr)
		if data == nil {
			return
		}
		c.sendEncryptedPacket(packetKindHelloFinish, []byte{}, addr)

		ch, ok := c.syncingHello.Load(addr)
		if !ok {
			return
		}
		select {
		case <-ch:
		default:
			close(ch)
			n := time.Now()
			c.remoteLastHello.Set(addr, n, n.Add(time.Minute))
			c.syncingHello.Delete(addr)
		}
	case packetKindHelloFinish:
		// TODO: figure this too
	case packetKindPing:
		c.sendPacket(packetKindPong, 0, c.publicKey[:], addr)
	case packetKindPong:
		state := c.getLockedRemoteState(addr)
		state.lastPong = time.Now()
		state.lastRoundTrip = state.lastPong.Sub(state.lastPing)
		state.mu.Unlock()
	case packetKindAck:
	case packetKindWholeData:
		c.handleEncryptedWholeData(data, addr)
	}
}

func (c *Client) readEncryptedPacket(pack []byte, flag uint8, addr netip.AddrPort) []byte {
	// obviously invalid packet
	if len(pack) < nonceSize+chacha20poly1305.Overhead {
		return nil
	}

	sharedKey, ok := c.getReceivingEncryptionKey(addr, flag)
	if !ok {
		return nil
	}
	cha, err := chacha20poly1305.NewX(sharedKey[:])
	if err != nil {
		return nil
	}

	iv := pack[:nonceSize]
	packData := pack[nonceSize:]

	open, err := cha.Open(packData[:0], iv, packData, []byte("kiwi"))
	if err != nil {
		return nil
	}

	return open
}

func (c *Client) handleEncryptedWholeData(pack []byte, addr netip.AddrPort) {
	data := c.readEncryptedPacket(pack, 0, addr)
	c.Handler(data, addr)
}
