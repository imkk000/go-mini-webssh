# WebSSH

A lightweight, web-based SSH terminal client written in Go.

> **Disclaimer:** This project was entirely vibe-coded using [Claude Code](https://claude.ai/code) by Anthropic.

## Features

- **Web-based SSH terminal** - Connect to SSH servers directly from your browser
- **Password authentication** - Standard username/password login
- **Private key authentication** - Paste PEM-encoded private keys with optional passphrase support
- **Terminal resizing** - Automatic terminal resize when the browser window changes
- **TLS/HTTPS support** - Optional TLS with certificate and key flags for secure connections
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

## Project Structure

```
.
├── main.go              # Go backend (WebSocket ↔ SSH proxy)
├── static/
│   ├── index.html       # Frontend (connect form + xterm.js terminal)
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
