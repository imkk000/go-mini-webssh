# WebSSH

A lightweight, web-based SSH terminal client written in Go.

> **Disclaimer:** This project was entirely vibe-coded using [Claude Code](https://claude.ai/code) by Anthropic.

## Features

- **Multi-tab sessions** - Open multiple SSH connections simultaneously as browser tabs; each tab is fully independent
- **Web-based SSH terminal** - Connect to SSH servers directly from your browser
- **Password & private key auth** - Standard password login or paste a PEM-encoded private key with optional passphrase
- **End-to-end encryption** - Every WebSocket session is protected with ECDH P-256 key exchange + AES-256-GCM; traffic is unreadable even in browser DevTools
- **Terminal resizing** - Automatic resize when the browser window changes
- **TLS/HTTPS support** - Optional TLS with `-cert`/`-key` flags for HTTPS/WSS
- **Auto-disconnect** - Sessions are closed cleanly when a tab is closed, the page is unloaded, or the remote shell exits
- **xterm.js v6** - Self-hosted terminal emulator, no external CDN dependencies
- **Nerd Font support** - Ships with Monaspace Argon Nerd Font Mono for icon rendering
- **Dark theme** - GitHub-inspired dark UI
- **Single binary** - No build tools or Node.js required at runtime

## Usage

```sh
# Default (HTTP on :8080)
go run main.go

# Custom address
go run main.go -addr :3000

# With TLS (HTTPS/WSS)
go run main.go -cert server.crt -key server.key
```

Then open `http://localhost:8080` in your browser.

## Build

```sh
go build -o webssh main.go
./webssh
```

## Docker

```sh
docker build -t webssh .
docker run -p 8080:8080 webssh
```

## Security model

Each WebSocket session uses a fresh ECDH P-256 key exchange to derive a shared AES-256-GCM key (via HKDF-SHA256). All subsequent frames — SSH credentials, terminal I/O, and resize events — are encrypted before being sent over the wire. The key exchange itself only transmits ephemeral public keys, so replaying captured traffic reveals nothing.

TLS (`-cert`/`-key`) adds a second layer and is recommended for production deployments.

## Project Structure

```
.
├── main.go              # Go backend (WebSocket ↔ SSH proxy, ECDH + AES-GCM)
├── static/
│   ├── index.html       # Frontend (multi-tab UI + xterm.js + Web Crypto)
│   └── vendor/
│       ├── xterm.js     # xterm.js v6.0.0
│       ├── xterm.css
│       ├── addon-fit.js # xterm fit addon v0.11.0
│       └── fonts/       # Monaspace Argon Nerd Font Mono
├── go.mod
└── go.sum
```

## License

MIT
