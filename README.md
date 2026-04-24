# WebSSH

A lightweight, web-based SSH terminal client written in Go.

> **Disclaimer:** This project was entirely vibe-coded using [Claude Code](https://claude.ai/code) by Anthropic.

## Features

- **Multi-tab sessions** - Open multiple SSH connections simultaneously as browser tabs; each tab is fully independent
- **Web-based SSH terminal** - Connect to SSH servers directly from your browser
- **Password & private key auth** - Standard password login or paste a PEM-encoded private key with optional passphrase
- **End-to-end encryption** - Every WebSocket session is protected with ECDH P-256 key exchange + AES-256-GCM; traffic is unreadable even in browser DevTools
- **WebSocket keepalive** - Server sends ping frames every 30 s to keep connections alive through nginx and other reverse proxies
- **Terminal resizing** - Automatic resize when the browser window changes
- **TLS/HTTPS support** - Optional TLS with `-cert`/`-key` flags for HTTPS/WSS
- **Light/Dark theme toggle** - Switch between GitHub-inspired dark and light themes; preference is saved across reloads
- **Mobile/tablet resize fix** - Terminal re-fits correctly when returning from another app on iPad or any mobile browser
- **Clear form** - One-click button to reset all connection fields back to defaults
- **Auto-disconnect** - Sessions are closed cleanly when a tab is closed, the page is unloaded, or the remote shell exits
- **xterm.js v6** - Self-hosted terminal emulator, no external CDN dependencies
- **Nerd Font support** - Ships with Monaspace Argon Nerd Font Mono for icon rendering
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

## Nginx reverse proxy

When running behind nginx, configure the WebSocket location with appropriate proxy timeouts.
`keepalive_timeout` controls HTTP keep-alive connections and has **no effect** on WebSocket sessions —
the relevant directive is `proxy_read_timeout`.

```nginx
location /ws {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;

    proxy_read_timeout 86400;
    proxy_send_timeout 86400;
}

location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
}
```

The server already sends WebSocket ping frames every 30 s to keep connections alive through proxies.

## Security model

Each WebSocket session uses a fresh ECDH P-256 key exchange to derive a shared AES-256-GCM key (via HKDF-SHA256). All subsequent frames — SSH credentials, terminal I/O, and resize events — are encrypted before being sent over the wire. The key exchange itself only transmits ephemeral public keys, so replaying captured traffic reveals nothing.

TLS (`-cert`/`-key`) adds a second layer and is recommended for production deployments.

## Project Structure

```
.
├── main.go              # Go backend (WebSocket ↔ SSH proxy, ECDH + AES-GCM, WS ping keepalive)
├── static/
│   ├── index.html       # Frontend (multi-tab UI + xterm.js + Web Crypto + light/dark theme)
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
