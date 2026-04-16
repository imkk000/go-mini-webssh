package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// ConnectConfig holds SSH connection parameters sent from the frontend.
type ConnectConfig struct {
	Host       string `json:"host"`
	Port       string `json:"port"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"` // PEM-encoded private key (optional)
	Passphrase string `json:"passphrase"`  // passphrase for the private key (optional)
}

// ResizeMsg is sent by the frontend when the terminal is resized.
type ResizeMsg struct {
	Type string `json:"type"`
	Cols uint32 `json:"cols"`
	Rows uint32 `json:"rows"`
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// Allow all origins; restrict in production via the CheckOrigin callback.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// safeWriter serialises concurrent WebSocket writes (gorilla/websocket is not
// goroutine-safe for concurrent writes).
type safeWriter struct {
	mu   sync.Mutex
	conn *websocket.Conn
}

func (sw *safeWriter) write(data []byte) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (sw *safeWriter) writeText(msg string) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	_ = sw.conn.WriteMessage(websocket.TextMessage, []byte(msg))
}

// buildAuthMethods constructs the SSH auth method list from the config.
// Private key auth is preferred when a key is provided; password auth is
// included as a fallback (or sole method) when a password is set.
func buildAuthMethods(cfg ConnectConfig) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if cfg.PrivateKey != "" {
		var signer ssh.Signer
		var err error

		if cfg.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(
				[]byte(cfg.PrivateKey), []byte(cfg.Passphrase),
			)
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(cfg.PrivateKey))
		}
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if cfg.Password != "" {
		methods = append(methods, ssh.Password(cfg.Password))
	}

	if len(methods) == 0 {
		return nil, fmt.Errorf("no authentication method provided (password or private key required)")
	}
	return methods, nil
}

// handleWS upgrades an HTTP connection to WebSocket and then proxies data
// between the browser and an SSH server.
func handleWS(w http.ResponseWriter, r *http.Request) {
	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade: %v", err)
		return
	}
	defer wsConn.Close()

	sw := &safeWriter{conn: wsConn}

	// ── 1. Read the first WebSocket message – SSH connection config ──────────
	wsConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		log.Printf("read config: %v", err)
		return
	}
	wsConn.SetReadDeadline(time.Time{}) // clear deadline

	var cfg ConnectConfig
	if err := json.Unmarshal(msg, &cfg); err != nil {
		sw.writeText(fmt.Sprintf("invalid config: %v\r\n", err))
		return
	}
	if cfg.Port == "" {
		cfg.Port = "22"
	}

	// ── 2. Build auth methods ────────────────────────────────────────────────
	authMethods, err := buildAuthMethods(cfg)
	if err != nil {
		sw.writeText(fmt.Sprintf("auth config error: %v\r\n", err))
		return
	}

	// ── 3. Dial SSH ──────────────────────────────────────────────────────────
	sshCfg := &ssh.ClientConfig{
		User:            cfg.Username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec – acceptable for a terminal proxy
		Timeout:         15 * time.Second,
	}

	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	sshClient, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		sw.writeText(fmt.Sprintf("\r\nSSH dial %s failed: %v\r\n", addr, err))
		return
	}
	defer sshClient.Close()
	log.Printf("SSH connected: %s@%s", cfg.Username, addr)

	// ── 4. Open an SSH session ───────────────────────────────────────────────
	session, err := sshClient.NewSession()
	if err != nil {
		sw.writeText(fmt.Sprintf("SSH session: %v\r\n", err))
		return
	}
	defer session.Close()

	// ── 5. Request a PTY ────────────────────────────────────────────────────
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 38400,
		ssh.TTY_OP_OSPEED: 38400,
	}
	if err := session.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		sw.writeText(fmt.Sprintf("PTY request: %v\r\n", err))
		return
	}

	sshIn, err := session.StdinPipe()
	if err != nil {
		sw.writeText(fmt.Sprintf("stdin pipe: %v\r\n", err))
		return
	}

	sshOut, err := session.StdoutPipe()
	if err != nil {
		sw.writeText(fmt.Sprintf("stdout pipe: %v\r\n", err))
		return
	}

	sshErr, err := session.StderrPipe()
	if err != nil {
		sw.writeText(fmt.Sprintf("stderr pipe: %v\r\n", err))
		return
	}

	if err := session.Shell(); err != nil {
		sw.writeText(fmt.Sprintf("shell: %v\r\n", err))
		return
	}

	// ── 6. Pipe SSH → WebSocket ──────────────────────────────────────────────
	done := make(chan struct{})

	copyToWS := func(src interface{ Read([]byte) (int, error) }) {
		buf := make([]byte, 4096)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if werr := sw.write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		select {
		case done <- struct{}{}:
		default:
		}
	}

	go copyToWS(sshOut)
	go copyToWS(sshErr)

	// ── 7. Pipe WebSocket → SSH (main goroutine) ─────────────────────────────
	for {
		_, data, err := wsConn.ReadMessage()
		if err != nil {
			break
		}

		// Check for a resize control message before forwarding as raw input.
		var resize ResizeMsg
		if json.Unmarshal(data, &resize) == nil && resize.Type == "resize" {
			if resize.Cols > 0 && resize.Rows > 0 {
				_ = session.WindowChange(int(resize.Rows), int(resize.Cols))
			}
			continue
		}

		if _, err := sshIn.Write(data); err != nil {
			break
		}
	}

	sshIn.Close()
	<-done
	log.Printf("session closed: %s@%s", cfg.Username, addr)
}

func main() {
	addr := flag.String("addr", ":8080", "listen address (host:port)")
	certFile := flag.String("cert", "", "TLS certificate file (enables HTTPS/WSS)")
	keyFile := flag.String("key", "", "TLS private key file")
	flag.Parse()

	http.Handle("/", http.FileServer(http.Dir("static")))
	http.HandleFunc("/ws", handleWS)

	if *certFile != "" && *keyFile != "" {
		log.Printf("WebSSH listening on https://%s (WSS enabled)", *addr)
		log.Fatal(http.ListenAndServeTLS(*addr, *certFile, *keyFile, nil))
	} else {
		log.Printf("WebSSH listening on http://%s (use -cert/-key for WSS)", *addr)
		log.Fatal(http.ListenAndServe(*addr, nil))
	}
}
