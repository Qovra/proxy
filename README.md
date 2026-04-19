# Hytale Proxy

A high-performance, purpose-built UDP proxy specifically designed for routing and protecting Hytale and other QUIC-based game servers. It features an advanced plugin-like handler architecture, hot-reloading without downtime, and deeply integrated networking capabilities to gracefully manage connections at scale.

## 🌟 Features

* **High-Performance UDP Forwarding**: Efficient and low-latency packet forwarding.
* **Intelligent SNI Routing**: Extracts Server Name Indication (SNI) right from the initial QUIC/TLS crypto frames, allowing you to run multiple Hytale servers on a single exposed port.
* **Load Balancing & Health Checking**: Supports multiple backends per SNI route. It utilizes round-robin load distribution and automatically performs lightweight UDP health pings to drop/reconnect unhealthy backends.
* **Hot Config Reloading**: Instantly reload your configuration files utilizing `SIGHUP` — completely preserving active player sessions and without goroutine leaks.
* **Modular Handler Chain architecture**: You can stack customizable rules and handlers right from the `config.json`.
* **Advanced Traffic Control**:
  * **`ip-ratelimit`**: Token bucket-based throttling guarding against connection spam (throttles connections-per-second).
  * **`ip-connlimit`**: Strict active connections capping with temporary `burst` allowances, preventing single IPs from claiming all resources.
* **Metrics & Analytics API**: A built-in HTTP server that exposes server uptime, total traffic analytics, and a real-time `/sessions` endpoint detailing active player addresses and their corresponding Usernames/UUIDs (when TLS termination is active).

## 🚀 Getting Started

Provide a robust `config.json` configuration file, customized to your routing layout:

```json
{
    "listen": ":5520",
    "metrics_listen": ":9090",
    "session_timeout": 7200,
    "handlers": [
        {
            "type": "ip-ratelimit",
            "config": {
                "max_conns_per_ip": 10,
                "refill_per_sec": 1
            }
        },
        {
            "type": "ip-connlimit",
            "config": {
                "max_conns_per_ip": 5,
                "burst": 3
            }
        },
        {
            "type": "sni-router",
            "config": {
                "routes": {
                    "play.myhytaleserver.com": [
                        "127.0.0.1:5521",
                        "127.0.0.1:5522"
                    ]
                }
            }
        },
        {
            "type": "forwarder"
        }
    ]
}
```

Then start the proxy:

```bash
go run cmd/proxy/main.go -config config.json
```

### Hot Reload

Apply changes to your `config.json` instantly without disturbing connected players:
```bash
kill -HUP $(pgrep -f proxy)
```

## 🙏 Credits

A huge thanks to the developers of **[HyBuildNet/quic-relay](https://github.com/HyBuildNet/quic-relay)**. This project has been heavily inspired by their awesome networking foundations and concepts!
