package proxy

import (
	"bytes"
	"container/heap"
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Qovra/core/internal/debug"
	"github.com/Qovra/core/internal/handler"
	"github.com/Qovra/core/internal/metrics"
)

const (
	maxCryptoBufferSize   = 8192
	writtenBitsetSize     = maxCryptoBufferSize / 64
	assemblerTimeout      = 5 * time.Second
	maxSessions           = 100000
	maxAssemblers         = 50000
	maxPendingPerDCID     = 10
	cleanupInterval       = 30 * time.Second
	defaultSessionTimeout = 7200
)

// CryptoAssembler collects CRYPTO frames from multiple Initial packets.
type CryptoAssembler struct {
	buffer    []byte
	written   []uint64
	maxOffset int
	complete  bool
	createdAt time.Time
	mu        sync.Mutex
	dcid      []byte
}

func NewCryptoAssembler() *CryptoAssembler {
	return &CryptoAssembler{
		buffer:    make([]byte, maxCryptoBufferSize),
		written:   make([]uint64, writtenBitsetSize),
		createdAt: time.Now(),
	}
}

func (a *CryptoAssembler) setBit(index int) {
	a.written[index/64] |= 1 << (index % 64)
}

func (a *CryptoAssembler) isSet(index int) bool {
	return a.written[index/64]&(1<<(index%64)) != 0
}

func (a *CryptoAssembler) AddFrame(offset uint64, data []byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if offset >= maxCryptoBufferSize {
		return false
	}
	end := int(offset) + len(data)
	if end > maxCryptoBufferSize {
		end = maxCryptoBufferSize
		data = data[:maxCryptoBufferSize-int(offset)]
	}
	copy(a.buffer[offset:end], data)
	for i := int(offset); i < end; i++ {
		a.setBit(i)
	}
	if end > a.maxOffset {
		a.maxOffset = end
	}
	return true
}

func (a *CryptoAssembler) TryParse() *handler.ClientHello {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.maxOffset < 6 {
		return nil
	}
	if a.buffer[0] != 0x01 {
		return nil
	}
	hsLen := int(a.buffer[1])<<16 | int(a.buffer[2])<<8 | int(a.buffer[3])
	needed := 4 + hsLen
	if needed > maxCryptoBufferSize {
		needed = maxCryptoBufferSize
	}
	if a.maxOffset < needed {
		return nil
	}
	for i := 0; i < needed; i++ {
		if !a.isSet(i) {
			return nil
		}
	}
	hello, err := parseTLSClientHello(a.buffer[:needed])
	if err != nil {
		return nil
	}
	a.complete = true
	return hello
}

func (a *CryptoAssembler) IsExpired() bool {
	return time.Since(a.createdAt) > assemblerTimeout
}

func (a *CryptoAssembler) IsComplete() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.complete
}

func (a *CryptoAssembler) InitCrypto(dcid []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if bytes.Equal(a.dcid, dcid) {
		return nil
	}
	a.dcid = make([]byte, len(dcid))
	copy(a.dcid, dcid)
	return nil
}

type pendingPacket struct {
	data []byte
}

type pendingBuffer struct {
	packets   []pendingPacket
	createdAt time.Time
	mu        sync.Mutex
}

// WorkItem represents a unit of work for the worker pool.
type WorkItem struct {
	ClientAddr *net.UDPAddr
	Packet     []byte
	Buffer     *[]byte
}

// WorkerPool manages a bounded set of goroutines for packet processing.
type WorkerPool struct {
	workers int
	queue   chan WorkItem
	handler func(*net.UDPAddr, []byte)
	wg      sync.WaitGroup
}

func NewWorkerPool(workers, queueSize int, h func(*net.UDPAddr, []byte)) *WorkerPool {
	if workers <= 0 {
		workers = 512
	}
	if queueSize <= 0 {
		queueSize = 4096
	}
	return &WorkerPool{
		workers: workers,
		queue:   make(chan WorkItem, queueSize),
		handler: h,
	}
}

func (wp *WorkerPool) Start() {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go func() {
			defer wp.wg.Done()
			for item := range wp.queue {
				wp.handler(item.ClientAddr, item.Packet)
				handler.PutBuffer(item.Buffer)
			}
		}()
	}
}

func (wp *WorkerPool) Submit(item WorkItem) bool {
	select {
	case wp.queue <- item:
		return true
	default:
		handler.PutBuffer(item.Buffer)
		return false
	}
}

func (wp *WorkerPool) Stop() {
	close(wp.queue)
	wp.wg.Wait()
}

// Proxy is the main UDP proxy server.
type Proxy struct {
	listenAddr     string
	conn           *net.UDPConn
	chain          atomic.Pointer[handler.Chain]
	sessionTimeout atomic.Int64
	sessions       sync.Map
	sessionCount   atomic.Int64
	assemblers     sync.Map
	pendingPackets sync.Map
	dcidAliases    sync.Map
	clientSessions sync.Map
	workerPool     *WorkerPool
	ctx            context.Context
	cancel         context.CancelFunc
	dcidLengths    map[int]struct{}
	dcidLengthsMu  sync.RWMutex
}

// New creates a new proxy instance.
func New(listenAddr string, chain *handler.Chain) *Proxy {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Proxy{
		listenAddr:  listenAddr,
		dcidLengths: make(map[int]struct{}),
		ctx:         ctx,
		cancel:      cancel,
	}
	p.chain.Store(chain)
	p.sessionTimeout.Store(defaultSessionTimeout)
	return p
}

// SetSessionTimeout updates the idle session timeout in seconds.
func (p *Proxy) SetSessionTimeout(seconds int) {
	if seconds <= 0 {
		seconds = defaultSessionTimeout
	}
	p.sessionTimeout.Store(int64(seconds))
}

// ReloadChain atomically replaces the handler chain and stops the old one.
// Any handler in the old chain that implements handler.Stopper will have its
// Stop() called to cleanly release goroutines and other resources.
func (p *Proxy) ReloadChain(chain *handler.Chain) {
	old := p.chain.Swap(chain)
	if old != nil {
		old.Stop()
	}
}

// SessionCount returns the number of active sessions.
func (p *Proxy) SessionCount() int {
	return int(p.sessionCount.Load())
}

// Run starts the proxy server.
func (p *Proxy) Run() error {
	handler.StartCoarseClock(p.ctx)

	addr, err := net.ResolveUDPAddr("udp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve address: %w", err)
	}

	p.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer p.conn.Close()

	log.Printf("[proxy] listening on %s", p.listenAddr)
	log.Printf("[proxy] session timeout: %ds", p.sessionTimeout.Load())

	p.workerPool = NewWorkerPool(0, 0, p.handlePacket)
	p.workerPool.Start()

	go p.cleanupSessions()

	for {
		select {
		case <-p.ctx.Done():
			return nil
		default:
		}

		buf := handler.GetBuffer()
		p.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := p.conn.ReadFromUDP(*buf)
		if err != nil {
			handler.PutBuffer(buf)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("[proxy] read error: %v", err)
			continue
		}

		if !p.workerPool.Submit(WorkItem{
			ClientAddr: clientAddr,
			Packet:     (*buf)[:n],
			Buffer:     buf,
		}) {
			debug.Printf("worker queue full, dropping packet from %s", clientAddr)
		}
	}
}

// Stop stops the proxy server gracefully.
func (p *Proxy) Stop() {
	p.cancel()
	if p.conn != nil {
		p.conn.Close()
	}
	if p.workerPool != nil {
		p.workerPool.Stop()
	}
	p.sessions.Range(func(key, value any) bool {
		ctx := value.(*handler.Context)
		p.chain.Load().OnDisconnect(ctx)
		p.deleteSession(key.(string), ctx)
		return true
	})
}

func (p *Proxy) handlePacket(clientAddr *net.UDPAddr, packet []byte) {
	debug.Printf("received %d bytes from %s", len(packet), clientAddr)

	pktType := ClassifyPacket(packet)
	ctx, dcid := p.findSession(packet, pktType, clientAddr)

	if ctx != nil {
		currentAddr := ctx.Session.ClientAddr()
		if !currentAddr.IP.Equal(clientAddr.IP) || currentAddr.Port != clientAddr.Port {
			log.Printf("[proxy] connection migration: %s -> %s", currentAddr, clientAddr)
			ctx.Session.SetClientAddr(clientAddr)
			dcidKey := string(ctx.Session.DCID)
			p.clientSessions.Delete(currentAddr.String())
			p.clientSessions.Store(clientAddr.String(), dcidKey)
		}
		result := p.chain.Load().OnPacket(ctx, packet, handler.Inbound)
		if result.Action == handler.Drop && result.Error != nil {
			log.Printf("[proxy] packet dropped: %v", result.Error)
		}
		return
	}

	if pktType != PacketInitial {
		if pktType == PacketZeroRTT || pktType == PacketHandshake {
			if dcid == nil {
				dcid, _ = ExtractDCID(packet, 0)
			}
			if dcid != nil {
				p.bufferPendingPacket(string(dcid), packet)
			}
		}
		return
	}

	if dcid == nil {
		var err error
		dcid, err = ExtractDCID(packet, 0)
		if err != nil {
			return
		}
	}
	dcidKey := string(dcid)

	assemblerVal, loaded := p.assemblers.LoadOrStore(dcidKey, NewCryptoAssembler())
	assembler := assemblerVal.(*CryptoAssembler)

	if loaded && assembler.IsExpired() {
		p.assemblers.Delete(dcidKey)
		assembler = NewCryptoAssembler()
		p.assemblers.Store(dcidKey, assembler)
	}

	if assembler.IsComplete() {
		return
	}

	frames, err := ExtractCryptoFramesFromPacket(packet)
	if err != nil {
		debug.Printf("CRYPTO extraction failed: %v", err)
	} else {
		for _, f := range frames {
			assembler.AddFrame(f.Offset, f.Data)
		}
	}

	hello := assembler.TryParse()
	if hello == nil {
		return
	}

	p.assemblers.Delete(dcidKey)
	log.Printf("[proxy] new connection: SNI=%q DCID=%x", hello.SNI, dcid)

	newCtx := &handler.Context{
		ClientAddr:    clientAddr,
		InitialPacket: packet,
		Hello:         hello,
		ProxyConn:     p.conn,
	}
	newCtx.Set("_session_count", p.sessionCount.Load())
	newCtx.OnServerPacket = func(pkt []byte) {
		p.learnServerSCID(dcidKey, newCtx, pkt)
	}

	result := p.chain.Load().OnConnect(newCtx)
	if result.Action == handler.Drop {
		if result.Error != nil {
			log.Printf("[proxy] connection dropped: %v", result.Error)
		}
		return
	}

	if result.Action == handler.Handled && newCtx.Session != nil {
		newCtx.Session.DCID = make([]byte, len(dcid))
		copy(newCtx.Session.DCID, dcid)
		p.registerDCIDLength(len(dcid))
		p.storeSession(dcidKey, newCtx)
		p.clientSessions.Store(clientAddr.String(), dcidKey)
		p.flushPendingPackets(dcidKey, newCtx)
		newCtx.DropSession = func() {
			p.chain.Load().OnDisconnect(newCtx)
			p.deleteSession(dcidKey, newCtx)
		}
	}
}

func (p *Proxy) findSession(packet []byte, pktType PacketType, clientAddr *net.UDPAddr) (*handler.Context, []byte) {
	if pktType == PacketShortHeader {
		p.dcidLengthsMu.RLock()
		lengths := make([]int, 0, len(p.dcidLengths))
		for l := range p.dcidLengths {
			lengths = append(lengths, l)
		}
		p.dcidLengthsMu.RUnlock()
		sort.Sort(sort.Reverse(sort.IntSlice(lengths)))

		for _, dcidLen := range lengths {
			dcid, err := ExtractDCID(packet, dcidLen)
			if err != nil {
				continue
			}
			dcidKey := string(dcid)
			if val, ok := p.sessions.Load(dcidKey); ok {
				return val.(*handler.Context), dcid
			}
			if originalKey, ok := p.dcidAliases.Load(dcidKey); ok {
				if val, ok := p.sessions.Load(originalKey.(string)); ok {
					return val.(*handler.Context), dcid
				}
			}
		}

		if clientAddr != nil {
			if originalDCID, ok := p.clientSessions.Load(clientAddr.String()); ok {
				if val, ok := p.sessions.Load(originalDCID.(string)); ok {
					return val.(*handler.Context), nil
				}
			}
		}
		return nil, nil
	}

	dcid, err := ExtractDCID(packet, 0)
	if err != nil {
		return nil, nil
	}
	dcidKey := string(dcid)

	if val, ok := p.sessions.Load(dcidKey); ok {
		return val.(*handler.Context), dcid
	}
	if originalKey, ok := p.dcidAliases.Load(dcidKey); ok {
		if val, ok := p.sessions.Load(originalKey.(string)); ok {
			return val.(*handler.Context), dcid
		}
	}
	if clientAddr != nil {
		if originalDCID, ok := p.clientSessions.Load(clientAddr.String()); ok {
			if val, ok := p.sessions.Load(originalDCID.(string)); ok {
				return val.(*handler.Context), dcid
			}
		}
	}
	return nil, dcid
}

func (p *Proxy) registerDCIDLength(length int) {
	p.dcidLengthsMu.Lock()
	p.dcidLengths[length] = struct{}{}
	p.dcidLengthsMu.Unlock()
}

func (p *Proxy) learnServerSCID(originalDCID string, _ *handler.Context, datagram []byte) {
	scids := ExtractAllSCIDs(datagram)
	for _, scid := range scids {
		scidKey := string(scid)
		if scidKey == originalDCID {
			continue
		}
		if _, exists := p.dcidAliases.Load(scidKey); exists {
			continue
		}
		p.dcidAliases.Store(scidKey, originalDCID)
		p.registerDCIDLength(len(scid))
		log.Printf("[proxy] learned server SCID=%x", scid)
	}
}

func (p *Proxy) storeSession(key string, ctx *handler.Context) {
	count := p.sessionCount.Add(1)
	if count >= maxSessions*9/10 {
		p.cleanupOldestSessions(int(count) / 10)
	}
	p.sessions.Store(key, ctx)
}

func (p *Proxy) deleteSession(key string, ctx *handler.Context) {
	if _, loaded := p.sessions.LoadAndDelete(key); loaded {
		p.sessionCount.Add(-1)
		if ctx != nil && ctx.Session != nil {
			if clientAddr := ctx.Session.ClientAddr(); clientAddr != nil {
				p.clientSessions.Delete(clientAddr.String())
			}
		}
	}
}

func (p *Proxy) bufferPendingPacket(dcidKey string, packet []byte) {
	val, _ := p.pendingPackets.LoadOrStore(dcidKey, &pendingBuffer{
		createdAt: time.Now(),
	})
	buf := val.(*pendingBuffer)
	buf.mu.Lock()
	defer buf.mu.Unlock()
	if len(buf.packets) >= maxPendingPerDCID {
		return
	}
	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)
	buf.packets = append(buf.packets, pendingPacket{data: pktCopy})
}

func (p *Proxy) flushPendingPackets(dcidKey string, ctx *handler.Context) {
	val, ok := p.pendingPackets.LoadAndDelete(dcidKey)
	if !ok {
		return
	}
	buf := val.(*pendingBuffer)
	buf.mu.Lock()
	packets := buf.packets
	buf.packets = nil
	buf.mu.Unlock()
	for _, pkt := range packets {
		p.chain.Load().OnPacket(ctx, pkt.data, handler.Inbound)
	}
}

func (p *Proxy) cleanupSessions() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			timeout := time.Duration(p.sessionTimeout.Load()) * time.Second
			p.sessions.Range(func(key, value any) bool {
				ctx := value.(*handler.Context)
				if ctx.Session != nil && ctx.Session.IdleDuration() > timeout {
					log.Printf("[proxy] cleaning up idle session: %s", key)
					p.chain.Load().OnDisconnect(ctx)
					p.deleteSession(key.(string), ctx)
				}
				return true
			})
			p.assemblers.Range(func(key, value any) bool {
				if value.(*CryptoAssembler).IsExpired() {
					p.assemblers.Delete(key)
				}
				return true
			})
			p.pendingPackets.Range(func(key, value any) bool {
				if time.Since(value.(*pendingBuffer).createdAt) > assemblerTimeout {
					p.pendingPackets.Delete(key)
				}
				return true
			})
		}
	}
}

type sessionAge struct {
	key  string
	idle time.Duration
}

type sessionHeap []sessionAge

func (h sessionHeap) Len() int           { return len(h) }
func (h sessionHeap) Less(i, j int) bool { return h[i].idle < h[j].idle }
func (h sessionHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *sessionHeap) Push(x any)        { *h = append(*h, x.(sessionAge)) }
func (h *sessionHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

func (p *Proxy) cleanupOldestSessions(n int) {
	if n <= 0 {
		return
	}
	h := &sessionHeap{}
	heap.Init(h)
	p.sessions.Range(func(key, value any) bool {
		ctx := value.(*handler.Context)
		if ctx.Session == nil {
			return true
		}
		age := sessionAge{key: key.(string), idle: ctx.Session.IdleDuration()}
		if h.Len() < n {
			heap.Push(h, age)
		} else if age.idle > (*h)[0].idle {
			heap.Pop(h)
			heap.Push(h, age)
		}
		return true
	})
	for h.Len() > 0 {
		age := heap.Pop(h).(sessionAge)
		if val, ok := p.sessions.Load(age.key); ok {
			ctx := val.(*handler.Context)
			p.chain.Load().OnDisconnect(ctx)
			p.deleteSession(age.key, ctx)
		}
	}
}

// TotalBytesIn returns the total bytes received from all sessions.
func (p *Proxy) TotalBytesIn() int64 {
	var total int64
	p.sessions.Range(func(_, value any) bool {
		ctx := value.(*handler.Context)
		if ctx.Session != nil {
			total += ctx.Session.BytesIn.Load()
		}
		return true
	})
	return total
}

// TotalBytesOut returns the total bytes sent to all sessions.
func (p *Proxy) TotalBytesOut() int64 {
	var total int64
	p.sessions.Range(func(_, value any) bool {
		ctx := value.(*handler.Context)
		if ctx.Session != nil {
			total += ctx.Session.BytesOut.Load()
		}
		return true
	})
	return total
}

// Sessions returns info about all active sessions.
func (p *Proxy) Sessions() []metrics.SessionInfo {
	var result []metrics.SessionInfo
	p.sessions.Range(func(_, value any) bool {
		ctx := value.(*handler.Context)
		if ctx.Session == nil {
			return true
		}
		sni := ""
		if ctx.Hello != nil {
			sni = ctx.Hello.SNI
		}
		result = append(result, metrics.SessionInfo{
			SNI:         sni,
			Backend:     ctx.GetString("backend"),
			ClientAddr:  ctx.Session.ClientAddr().String(),
			Username:    ctx.Session.Username,
			PlayerUUID:  ctx.Session.PlayerUUID,
			BytesIn:     ctx.Session.BytesIn.Load(),
			BytesOut:    ctx.Session.BytesOut.Load(),
			IdleSecs:    ctx.Session.IdleDuration().Seconds(),
			ConnectedAt: ctx.Session.CreatedAt.Format(time.RFC3339),
		})
		return true
	})
	return result
}
