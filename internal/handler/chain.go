package handler

// Action represents the result action from a handler.
type Action int

const (
	// Continue passes control to the next handler in the chain.
	Continue Action = iota
	// Handled indicates the handler has fully processed the request.
	Handled
	// Drop discards the connection or packet.
	Drop
)

// Result is returned by handler methods.
type Result struct {
	Action Action
	Error  error
}

// Direction indicates the packet flow direction.
type Direction int

const (
	// Inbound represents packets from client to proxy.
	Inbound Direction = iota
	// Outbound represents packets from backend to client.
	Outbound
)

// Handler is the interface that all handlers must implement.
type Handler interface {
	Name() string
	OnConnect(ctx *Context) Result
	OnPacket(ctx *Context, packet []byte, dir Direction) Result
	OnDisconnect(ctx *Context)
}

// Chain executes handlers in sequence.
type Chain struct {
	handlers []Handler
}

// NewChain creates a new handler chain.
func NewChain(handlers ...Handler) *Chain {
	return &Chain{handlers: handlers}
}

// OnConnect processes a new connection through the chain.
func (c *Chain) OnConnect(ctx *Context) Result {
	for _, h := range c.handlers {
		result := h.OnConnect(ctx)
		if result.Action != Continue {
			return result
		}
	}
	return Result{Action: Drop}
}

// OnPacket processes a packet through the chain.
func (c *Chain) OnPacket(ctx *Context, packet []byte, dir Direction) Result {
	for _, h := range c.handlers {
		result := h.OnPacket(ctx, packet, dir)
		if result.Action != Continue {
			return result
		}
	}
	return Result{Action: Drop}
}

// OnDisconnect notifies all handlers of disconnection.
func (c *Chain) OnDisconnect(ctx *Context) {
	for _, h := range c.handlers {
		h.OnDisconnect(ctx)
	}
}

// Handlers returns the list of handlers in the chain.
func (c *Chain) Handlers() []Handler {
	return c.handlers
}
