hytale-proxy/
├── cmd/proxy/
│   └── main.go                  # entrypoint, flags, SIGHUP reload
├── internal/
│   ├── handler/
│   │   ├── chain.go             # Chain, Handler interface, Action/Result/Direction
│   │   ├── context.go           # Context, Session, buffer pool, coarse clock
│   │   ├── registry.go          # Register(), BuildChain()
│   │   ├── sni_router.go        # DynamicHandler (ya tenés esto)
│   │   ├── ip_ratelimit.go      # RateLimitHandler por IP (nuevo)
│   │   ├── terminator.go        # TerminatorHandler (ya tenés esto)
│   │   └── forwarder.go         # ForwarderHandler (ya tenés esto)
│   ├── proxy/
│   │   ├── proxy.go             # Proxy, sesiones, worker pool, cleanup
│   │   ├── parser.go            # QUIC parsing, CRYPTO frames, ClientHello
│   │   └── config.go            # Config, LoadConfig, ParseConfig
│   ├── proto/
│   │   ├── packet.go            # Packet, zstd decompress
│   │   ├── connect.go           # ConnectPacket, ParseConnect
│   │   └── strings.go           # ReadString, VarInt helpers
│   ├── metrics/
│   │   └── server.go            # HTTP /metrics, /health, /sessions
│   └── debug/
│       └── debug.go             # debug.Printf, Enable()
├── config/
│   └── example.json
└── go.mod


Nos faltan:
cmd/proxy/main.go
config/example.json