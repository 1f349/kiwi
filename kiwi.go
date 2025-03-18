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
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const nonceSize = chacha20poly1305.NonceSizeX

var pingData = []byte{
	16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
	26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
	36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
	46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
}

type Handler func(b []byte, addr netip.AddrPort)

type Client struct {
	Conn    *net.UDPConn
	Handler Handler

	// FilterIP returns true if the remote connection is allowed to proceed.
	// This allows for dropping connections before any parsing or decrypting is done.
	// The provided function must be thread-safe.
	FilterIP func(addr netip.AddrPort) bool

	PrivateKey Key
	PublicKey  Key

	cryptoTimeout time.Time

	remoteState syncmap.Map[netip.AddrPort, *remoteStateItem]

	peers syncmap.Map[netip.Addr, Key]

	syncingHello syncmap.Map[netip.AddrPort, chan struct{}]

	remoteLastHello *cache.Cache[netip.AddrPort, time.Time]

	// client state
	running atomic.Bool

	// wg is the wait group for internal goroutines
	wg sync.WaitGroup

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

	seq Seq

	// resend contains an array of the previous 20 packets to send
	resend *cache.Cache[Seq, []byte]

	// ackChan contains the channel to signal when an ack is returned
	ackChan *cache.Cache[Seq, chan<- time.Time]

	// lastPing contains the last time a ping was sent to the remote connection
	lastPing time.Time
	// lastPong contains the last time a pong was received from the remote connection
	lastPong time.Time
	// lastRoundTrip contains the duration for the last full ping<->pong round trip
	lastRoundTrip time.Duration
}

func newRemoteStateItem() remoteStateItem {
	return remoteStateItem{
		resend:  cache.New[Seq, []byte](),
		ackChan: cache.New[Seq, chan<- time.Time](),
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
			state.seq = RandSeq()
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

var ErrDataTooLong = errors.New("data too long: maximum packet size is 900 bytes")

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
	state.seq = state.seq.Increment()
	state.mu.Unlock()
	b := encode(kind, seq, data)
	seq = seq.AddMeta(flag, ack != nil)
	if ack != nil {
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
	return c.getGenericEncryptionKey(addr, flag, c.PublicKey)
}

func (c *Client) getGenericEncryptionKey(addr netip.AddrPort, flag uint8, publicKey Key) (Key, bool) {
	peerPubKey, ok := c.peers.Load(addr.Addr())
	if !ok {
		return [KeyLen]byte{}, false
	}
	peerSharedKey, err := c.PrivateKey.SharedKey(peerPubKey)
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
		b := make([]byte, 1500)
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
	// if FilterIP returns false then drop the connection
	if c.FilterIP != nil && !c.FilterIP(addr) {
		return
	}

	kind, seq, data, err := decode(b)
	if err != nil {
		return
	}

	// use the upper 4 bits of seq for the encryption flag
	encFlag := seq.MinuteHint()

	// handle packet types
	switch kind {
	case packetKindHello:
		data, err = c.readEncryptedPacket(data, encFlag, addr)
		if err != nil {
			return
		}
		_ = c.sendEncryptedPacket(packetKindHelloVerify, data, addr, nil)
	case packetKindHelloVerify:
		data, err = c.readEncryptedPacket(data, 0, addr)
		if err != nil {
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
		_ = c.sendPacket(packetKindPong, 0, pingData, addr, nil)
	case packetKindPong:
		state := c.getLockedRemoteState(addr)
		state.lastPong = time.Now()
		state.lastRoundTrip = state.lastPong.Sub(state.lastPing)
		state.mu.Unlock()
	case packetKindAck:
		data, err = c.readEncryptedPacket(data, 0, addr)
		if err != nil {
			return
		}
		state := c.getReadLockedRemoteState(addr)
		ackChan, ok := state.ackChan.Get(Seq(binary.LittleEndian.Uint32(data)))
		if !ok {
			return
		}
		ackChan <- time.Now()
		state.mu.RUnlock()
	case packetKindData:
		c.handleEncryptedData(seq, data, addr)
	}
}

func (c *Client) readEncryptedPacket(pack []byte, flag uint8, addr netip.AddrPort) ([]byte, error) {
	// obviously invalid packet
	if len(pack) < nonceSize+chacha20poly1305.Overhead {
		return nil, errInvalidPacketLength
	}

	sharedKey, ok := c.getReceivingEncryptionKey(addr, flag)
	if !ok {
		return nil, ErrUnknownPeer
	}
	cha, err := chacha20poly1305.NewX(sharedKey[:])
	if err != nil {
		return nil, errInvalidPacketStructure
	}

	iv := pack[:nonceSize]
	packData := pack[nonceSize:]

	open, err := cha.Open(packData[:0], iv, packData, []byte("kiwi"))
	if err != nil {
		return nil, errInvalidPacketStructure
	}

	return open, nil
}

func (c *Client) handleEncryptedData(seq Seq, pack []byte, addr netip.AddrPort) {
	data, err := c.readEncryptedPacket(pack, 0, addr)
	if err != nil {
		return
	}

	// send ack only if the packet is decrypted properly
	if seq.RequestsAck() {
		ackData := binary.LittleEndian.AppendUint32(nil, uint32(seq))
		_ = c.sendEncryptedPacket(packetKindAck, ackData, addr, nil)
	}

	// at this point the handler is already wrapped in a
	// goroutine so it is safe to return to the user
	// controlled handler function
	c.Handler(data, addr)
}
