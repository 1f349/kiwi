package kiwi

import (
	"crypto/rsa"
	"crypto/sha256"
	"github.com/1f349/cache"
	"github.com/1f349/syncmap"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const cryptoTimeWeight = 30 * time.Second

type Handler func(b []byte, addr netip.AddrPort)

type Client struct {
	Conn       *net.UDPConn
	Handler    Handler
	BufferSize int

	RemotePublicKey *rsa.PublicKey

	privateKey Key
	publicKey  Key

	cryptoTimeout time.Time

	remoteState syncmap.Map[netip.AddrPort, *remoteStateItem]

	sessionKeys syncmap.Map[netip.AddrPort, AesKey]

	peers syncmap.Map[KeyHash, *remoteStateItem]

	// client state
	running atomic.Bool
}

type KeyHash [32]byte

type AesKey [32]byte

type remoteStateItem struct {
	mu sync.RWMutex

	publicKey Key
	seq       uint32

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

// getLockedRemoteState safely find *remoteStateItem for a given AddrPort and
// returns with the mu.Lock() set
func (c *Client) getLockedRemoteState(addr netip.AddrPort) *remoteStateItem {
	state, loaded := c.remoteState.Load(addr)
	if !loaded {
		// try to store a new remote state
		newState := newRemoteStateItem()
		newState.mu.Lock()
		state, loaded = c.remoteState.LoadOrStore(addr, &newState)

		// if the new state is stored then create a sequence number
		if !loaded {
			state.seq = rand.Uint32()
		}
	}

	// lock all loaded states
	// this will ignore the stored newState above
	if loaded {
		state.mu.Lock()
	}

	return state
}

func (c *Client) Send(b []byte, addr netip.AddrPort) {
	// TODO: add this
}

func (c *Client) sendPacket(kind packetKind, data []byte, addr netip.AddrPort) {
	state := c.getLockedRemoteState(addr)
	seq := state.seq
	state.seq++
	state.mu.Unlock()
	b := encode(kind, seq, data)
	state.resend.Set(seq, b, time.Now().Add(1*time.Minute))
	_, _ = c.Conn.WriteToUDPAddrPort(b, addr)
}

func (c *Client) internalRunner() {
	for {
		b := make([]byte, 4096)
		n, addr, err := c.Conn.ReadFromUDPAddrPort(b)
		if err != nil {
			continue
		}

		go c.handlePacket(b[:n], addr)
	}
}

func (c *Client) ping(addr netip.AddrPort) {
	state := c.getLockedRemoteState(addr)
	state.lastPing = time.Now()
	state.mu.Unlock()
}

func (c *Client) handlePacket(b []byte, addr netip.AddrPort) {
	kind, data, err := decode(b)
	if err != nil {
		return
	}

	// handle packet types
	switch kind {
	case packetKindClientHello:
		key, err := NewKey(data)
		if err != nil {
			return
		}
		state := c.getLockedRemoteState(addr)
		state.publicKey = key
		state.mu.Unlock()

		// 32 bytes - calculate sha256 public key to self identify to the server
		h := sha256.Sum256(c.publicKey[:])

		c.sendPacket(packetKindHelloVerify, h[:], addr)
	case packetKindHelloVerify:
		state := c.getLockedRemoteState(addr)
		state.publicKey = state.publicKey
	case packetKindServerHello:
	case packetKindPing:
		c.sendPacket(packetKindPong, c.publicKey[:], addr)
	case packetKindPong:
		state := c.getLockedRemoteState(addr)
		state.lastPong = time.Now()
		state.lastRoundTrip = state.lastPong.Sub(state.lastPing)
		state.mu.Unlock()
	case packetKindAck:
	case packetKindUserData:
		// TODO(melon): process crypto sync
		go c.Handler(data, addr)
	}
}
