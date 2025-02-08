package kiwi

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
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

	segmentPieces syncmap.Map[segmentKey, *segmentData]
	segmentId     atomic.Uint32

	syncingHello syncmap.Map[netip.AddrPort, chan struct{}]

	remoteLastHello *cache.Cache[netip.AddrPort, time.Time]

	// client state
	running atomic.Bool

	// wg is the wait group for internal goroutines
	wg sync.WaitGroup

	// wrDone is the done channel for internalWriter
	wrDone *donechan.DoneChan
}

type segmentKey struct {
	AddrPort  netip.AddrPort
	SegmentId uint32
}

type segmentData struct {
	mu     *sync.Mutex
	pieces [][]byte
	sent   bool
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

	// ackChan contains the channel to signal when an ack is returned
	ackChan *cache.Cache[uint32, chan<- time.Time]

	// lastPing contains the last time a ping was sent to the remote connection
	lastPing time.Time
	// lastPong contains the last time a pong was received from the remote connection
	lastPong time.Time
	// lastRoundTrip contains the duration for the last full ping<->pong round trip
	lastRoundTrip time.Duration
}

func newRemoteStateItem() remoteStateItem {
	return remoteStateItem{
		resend:  cache.New[uint32, []byte](),
		ackChan: cache.New[uint32, chan<- time.Time](),
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
	c.wrDone.Close()
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

const maxChunkSize = 900

var ErrDataTooLong = errors.New("data too long")

func (c *Client) Send(b []byte, addr netip.AddrPort) error {
	if len(b) > maxChunkSize {
		return ErrDataTooLong
	}

	c.internalHello(addr)
	return c.sendEncryptedPacket(packetKindData, b, addr, nil)
}

func (c *Client) SendWithAck(b []byte, addr netip.AddrPort) (<-chan time.Time, error) {
	if len(b) > maxChunkSize {
		return nil, ErrDataTooLong
	}

	c.internalHello(addr)

	ack := make(chan time.Time)
	err := c.sendEncryptedPacket(packetKindData, b, addr, ack)
	return ack, err
}

func (c *Client) sendPacket(kind packetKind, flag uint8, data []byte, addr netip.AddrPort, ack chan<- time.Time) error {
	state := c.getLockedRemoteState(addr)
	seq := state.seq
	state.seq++
	state.mu.Unlock()
	b := encode(kind, seq, data)
	seq &= 0x7_ff_ff
	seq |= uint32(flag) << (32 - 4)
	if ack != nil {
		seq &= 1 << (32 - 5)
		state.ackChan.Set(seq, ack, 2*time.Minute)
	}
	state.resend.Set(seq, b, 1*time.Minute)
	_, err := c.Conn.WriteToUDPAddrPort(b, addr)
	return err
}

var ErrUnknownPeer = errors.New("unknown peer")

func (c *Client) sendEncryptedPacket(kind packetKind, data []byte, addr netip.AddrPort, ack chan<- time.Time) error {
	sharedKey, ok := c.getSendingEncryptionKey(addr)
	if !ok {
		return ErrUnknownPeer
	}
	cha, err := chacha20poly1305.NewX(sharedKey[:])
	if err != nil {
		return fmt.Errorf("chacha20poly1305: %w", err)
	}

	packLen := nonceSize + chacha20poly1305.Overhead + len(data)
	iv := make([]byte, nonceSize, packLen)
	_, err = rand.Read(iv)
	if err != nil {
		return fmt.Errorf("rand.Read: %w", err)
	}

	// use the upper 4 bits of seq for the encryption flag
	encFlag := uint8(time.Now().UTC().Minute() % 10)

	pack := cha.Seal(iv, iv, data, []byte("kiwi"))

	return c.sendPacket(kind, encFlag, pack, addr, ack)
}

func (c *Client) getSendingEncryptionKey(addr netip.AddrPort) (Key, bool) {
	key, loaded := c.peers.Load(addr.Addr())
	if !loaded {
		return Key{}, false
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
	_ = c.sendEncryptedPacket(packetKindHello, b[:], addr, nil)

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
		_ = c.sendEncryptedPacket(packetKindHelloVerify, data, addr, nil)
	case packetKindHelloVerify:
		data = c.readEncryptedPacket(data, 0, addr)
		if data == nil {
			return
		}
		_ = c.sendEncryptedPacket(packetKindHelloFinish, []byte{}, addr, nil)

		ch, ok := c.syncingHello.Load(addr)
		if !ok {
			return
		}
		select {
		case <-ch:
		default:
			close(ch)
			n := time.Now()
			c.remoteLastHello.Set(addr, n, time.Minute)
			c.syncingHello.Delete(addr)
		}
	case packetKindHelloFinish:
		// TODO: figure this too
	case packetKindPing:
		_ = c.sendPacket(packetKindPong, 0, c.publicKey[:], addr, nil)
	case packetKindPong:
		state := c.getLockedRemoteState(addr)
		state.lastPong = time.Now()
		state.lastRoundTrip = state.lastPong.Sub(state.lastPing)
		state.mu.Unlock()
	case packetKindAck:
		data = c.readEncryptedPacket(data, 0, addr)
		if data == nil {
			return
		}
		state := c.getReadLockedRemoteState(addr)
		ackChan, ok := state.ackChan.Get(binary.LittleEndian.Uint32(data))
		if !ok {
			return
		}
		ackChan <- time.Now()
		state.mu.RUnlock()
	case packetKindData:
		isAck := (seq>>(32-5))&1 == 1
		if isAck {
			_ = c.sendEncryptedPacket(packetKindAck, binary.LittleEndian.AppendUint32(nil, seq), addr, nil)
		}
		c.handleEncryptedData(data, addr)
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

func (c *Client) handleEncryptedData(pack []byte, addr netip.AddrPort) {
	data := c.readEncryptedPacket(pack, 0, addr)
	c.Handler(data, addr)
}
