package handler

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ClientHello contains parsed TLS ClientHello data.
type ClientHello struct {
	SNI           string
	ALPNProtocols []string
	Raw           []byte
}

// Session holds the state of an active proxied connection.
type Session struct {
	ID          uint64
	BackendAddr *net.UDPAddr
	BackendConn *net.UDPConn
	CreatedAt   time.Time
	DCID        []byte

	clientAddr   atomic.Pointer[net.UDPAddr]
	LastActivity atomic.Int64
	closed       atomic.Bool

	BytesIn  atomic.Int64
	BytesOut atomic.Int64

	// Player info (populated by terminator if TLS termination is enabled)
	Username   string
	PlayerUUID string
}

// SetClientAddr atomically sets the client address.
func (s *Session) SetClientAddr(addr *net.UDPAddr) {
	s.clientAddr.Store(addr)
}

// ClientAddr atomically gets the client address.
func (s *Session) ClientAddr() *net.UDPAddr {
	return s.clientAddr.Load()
}

// Touch updates the last activity timestamp.
func (s *Session) Touch() {
	s.LastActivity.Store(time.Now().Unix())
}

// IdleDuration returns how long the session has been idle.
func (s *Session) IdleDuration() time.Duration {
	last := s.LastActivity.Load()
	return time.Since(time.Unix(last, 0))
}

// Close atomically marks the session as closed.
// Returns true if this call did the closing, false if already closed.
func (s *Session) Close() bool {
	return s.closed.CompareAndSwap(false, true)
}

// IsClosed returns whether the session is closed.
func (s *Session) IsClosed() bool {
	return s.closed.Load()
}

// Context holds all state for a single proxied connection.
type Context struct {
	ClientAddr    *net.UDPAddr
	InitialPacket []byte
	Hello         *ClientHello
	ProxyConn     *net.UDPConn
	Session       *Session

	// DropSession can be called by handlers to immediately terminate a session.
	DropSession func()

	// OnServerPacket is called when a packet arrives from the backend.
	OnServerPacket func(packet []byte)

	values sync.Map
}

// Set stores a value in the context.
func (c *Context) Set(key string, value any) {
	c.values.Store(key, value)
}

// Get retrieves a value from the context.
func (c *Context) Get(key string) (any, bool) {
	return c.values.Load(key)
}

// GetString retrieves a string value from the context.
func (c *Context) GetString(key string) string {
	val, ok := c.values.Load(key)
	if !ok {
		return ""
	}
	s, _ := val.(string)
	return s
}

// NotifyServerPacket calls OnServerPacket if set.
func (c *Context) NotifyServerPacket(packet []byte) {
	if c.OnServerPacket != nil {
		c.OnServerPacket(packet)
	}
}

// --- Buffer pool ---

var bufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 65535)
		return &buf
	},
}

// GetBuffer returns a buffer from the pool.
func GetBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

// PutBuffer returns a buffer to the pool.
func PutBuffer(buf *[]byte) {
	bufferPool.Put(buf)
}

// --- Coarse clock ---

var coarseClock atomic.Int64

// StartCoarseClock starts a goroutine that updates a coarse clock every second.
func StartCoarseClock(ctx interface{ Done() <-chan struct{} }) {
	coarseClock.Store(time.Now().Unix())
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case t := <-ticker.C:
				coarseClock.Store(t.Unix())
			}
		}
	}()
}
