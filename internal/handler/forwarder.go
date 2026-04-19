package handler

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"sync/atomic"
	"time"
)

func init() {
	Register("forwarder", NewForwarderHandler)
}

// ForwarderHandler handles UDP packet forwarding between clients and backends.
type ForwarderHandler struct {
	sessionCounter atomic.Uint64
}

// NewForwarderHandler creates a new forwarder handler.
func NewForwarderHandler(_ json.RawMessage) (Handler, error) {
	return &ForwarderHandler{}, nil
}

func (h *ForwarderHandler) Name() string {
	return "forwarder"
}

// OnConnect establishes a UDP session to the backend.
func (h *ForwarderHandler) OnConnect(ctx *Context) Result {
	backend := ctx.GetString("backend")
	if backend == "" {
		return Result{Action: Drop, Error: errors.New("no backend address")}
	}

	backendAddr, err := net.ResolveUDPAddr("udp", backend)
	if err != nil {
		return Result{Action: Drop, Error: err}
	}

	backendConn, err := net.DialUDP("udp", nil, backendAddr)
	if err != nil {
		return Result{Action: Drop, Error: err}
	}

	now := time.Now()
	session := &Session{
		ID:          h.sessionCounter.Add(1),
		BackendAddr: backendAddr,
		BackendConn: backendConn,
		CreatedAt:   now,
	}
	session.SetClientAddr(ctx.ClientAddr)
	session.LastActivity.Store(now.Unix())
	ctx.Session = session

	log.Printf("[forwarder] session=%d %s -> %s", session.ID, ctx.ClientAddr, backend)

	if len(ctx.InitialPacket) > 0 {
		if _, err := backendConn.Write(ctx.InitialPacket); err != nil {
			log.Printf("[forwarder] failed to forward initial packet: %v", err)
			backendConn.Close()
			return Result{Action: Drop, Error: err}
		}
	}

	ctx.InitialPacket = nil
	go h.backendToClient(ctx, session)

	return Result{Action: Handled}
}

// OnPacket forwards packets from client to backend.
func (h *ForwarderHandler) OnPacket(ctx *Context, packet []byte, dir Direction) Result {
	if ctx.Session == nil {
		return Result{Action: Drop, Error: errors.New("no session")}
	}
	if ctx.Session.IsClosed() {
		return Result{Action: Drop}
	}

	ctx.Session.Touch()

	if dir == Inbound {
		ctx.Session.BytesIn.Add(int64(len(packet)))
		if _, err := ctx.Session.BackendConn.Write(packet); err != nil {
			log.Printf("[forwarder] write to backend failed: %v", err)
			return Result{Action: Drop, Error: err}
		}
	}

	return Result{Action: Handled}
}

// OnDisconnect cleans up the session.
func (h *ForwarderHandler) OnDisconnect(ctx *Context) {
	if ctx.Session != nil {
		if !ctx.Session.Close() {
			return
		}
		log.Printf("[forwarder] closing session=%d duration=%v bytes_in=%d bytes_out=%d",
			ctx.Session.ID,
			time.Since(ctx.Session.CreatedAt),
			ctx.Session.BytesIn.Load(),
			ctx.Session.BytesOut.Load(),
		)
		ctx.Session.BackendConn.Close()
	}
}

// backendToClient reads packets from backend and sends to client.
func (h *ForwarderHandler) backendToClient(ctx *Context, session *Session) {
	for {
		if session.IsClosed() {
			return
		}

		buf := GetBuffer()
		session.BackendConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, err := session.BackendConn.Read(*buf)
		if err != nil {
			PutBuffer(buf)
			return
		}

		if session.IsClosed() {
			PutBuffer(buf)
			return
		}

		session.Touch()
		session.BytesOut.Add(int64(n))
		ctx.NotifyServerPacket((*buf)[:n])

		if ctx.ProxyConn != nil {
			if _, err := ctx.ProxyConn.WriteToUDP((*buf)[:n], session.ClientAddr()); err != nil {
				log.Printf("[forwarder] write to client failed: %v", err)
				PutBuffer(buf)
				return
			}
		}

		PutBuffer(buf)
	}
}
