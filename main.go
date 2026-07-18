// Veil is the official P2P messaging application.
// Official source: https://github.com/GNU-LuxTech/Veil

/*
Copyright (c) 2026 Veil. All rights reserved.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
*/

package main

import (
	"bufio"
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/cretz/bine/tor"
	"github.com/cretz/bine/torutil"
	torutil_ed25519 "github.com/cretz/bine/torutil/ed25519"
	"golang.org/x/crypto/chacha20poly1305"
)

//go:embed tor.exe
var torBinary []byte

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFDF5")).
			Background(lipgloss.Color("#6124DF")).
			Padding(0, 1).
			Bold(true)

	peerMsgStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
	myMsgStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)
	infoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Italic(true)
)

func main() {
	// Parse command line flags
	listenFlag := flag.Bool("listen", false, "Listen for incoming connections")
	connectFlag := flag.String("connect", "", "Connect to a peer's onion address")
	flag.Parse()

	printBanner()

	if !*listenFlag && *connectFlag == "" {
		fmt.Println("  [VEIL] Please specify --listen or --connect <address>")
		os.Exit(1)
	}

	// Step 1: Generate Identity
	fmt.Println("  [VEIL] generating identity keypair...")
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("failed to generate keypair", err)
	}

	// Step 1.5: Extract Embedded Tor
	extractedExe := extractTor(*listenFlag)

	// Step 2: Start Tor Daemon
	fmt.Println("  [VEIL] starting tor daemon (may take 30-60s)...")
	torConf := &tor.StartConf{
		DataDir: torDataDir(*listenFlag),
		ExePath: extractedExe, // Point to our newly extracted binary!
		ExtraArgs: []string{
			"--quiet",
			"--Log", "notice file " + filepath.Join(torDataDir(*listenFlag), "tor.log"),
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	t, err := tor.Start(ctx, torConf)
	if err != nil {
		fatal("failed to start tor", err)
	}
	defer t.Close()
	fmt.Println("  [VEIL] tor daemon started.")

	// Branch based on mode
	if *listenFlag {
		runListener(t, privateKey)
	} else if *connectFlag != "" {
		runDialer(t, *connectFlag, privateKey)
	}
}

// extractTor writes the embedded tor.exe to the data directory so we can run it
func extractTor(isListener bool) string {
	dataDir := torDataDir(isListener)
	
	// Ensure the directory exists
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		fatal("failed to create tor data directory", err)
	}

	exePath := filepath.Join(dataDir, "tor.exe")
	
	// Check if we already extracted it (to save time on reboot)
	if _, err := os.Stat(exePath); os.IsNotExist(err) {
		fmt.Println("  [VEIL] extracting embedded tor binary...")
		if err := os.WriteFile(exePath, torBinary, 0700); err != nil {
			fatal("failed to extract tor binary", err)
		}
	}
	
	return exePath
}

// runListener handles incoming connections
func runListener(t *tor.Tor, privateKey ed25519.PrivateKey) {
	fmt.Println("  [VEIL] creating onion service...")
	listenCtx, listenCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer listenCancel()

	onion, err := t.Listen(listenCtx, &tor.ListenConf{
		RemotePorts: []int{7777},
		Key:         privateKey,
		Version3:    true,
	})
	if err != nil {
		fatal("failed to create onion service", err)
	}
	defer onion.Close()

	fmt.Printf("\n  [VEIL] listening at: %s.onion\n\n", onion.ID)

	for {
		conn, err := onion.Accept()
		if err != nil {
			fmt.Println("  [ERROR] failed to accept connection:", err)
			continue
		}
		
		fmt.Println("  [VEIL] incoming connection received! authenticating...")
		
		peerAddress, aead, err := performHandshake(conn, true, privateKey)
		if err != nil {
			fmt.Println("  [ERROR] connection rejected (handshake failed):", err)
			conn.Close()
			continue
		}

		fmt.Printf("\n  [!] INCOMING CONNECTION FROM: %s.onion\n", peerAddress)
		fmt.Print("  Accept? (y/n): ")
		
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		
		if response != "y" && response != "yes" {
			fmt.Println("  [VEIL] connection rejected.")
			conn.Write([]byte{0x00}) // Tell the dialer we rejected
			conn.Close()
			continue
		}
		
		conn.Write([]byte{0x01}) // Tell the dialer we accepted
		handleSession(conn, aead, peerAddress)
		
		fmt.Println("  [VEIL] session closed.")
		conn.Close()
	}
}

// runDialer connects to another Veil node
func runDialer(t *tor.Tor, targetAddress string, privateKey ed25519.PrivateKey) {
	targetAddress = strings.TrimSuffix(targetAddress, ".onion")
	fmt.Printf("  [VEIL] connecting to %s.onion ...\n", targetAddress)
	
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer dialCancel()

	dialer, err := t.Dialer(dialCtx, nil)
	if err != nil {
		fatal("failed to get tor dialer", err)
	}

	conn, err := dialer.DialContext(dialCtx, "tcp", targetAddress+".onion:7777")
	if err != nil {
		fatal("connection failed", err)
	}
	defer conn.Close()

	peerAddress, aead, err := performHandshake(conn, false, privateKey)
	if err != nil {
		fatal("handshake failed", err)
	}
	
	if peerAddress != targetAddress {
		fatal("MITM DETECTED!", fmt.Errorf("expected server %s.onion, but got %s.onion", targetAddress, peerAddress))
	}

	fmt.Println("  [VEIL] identity verified! waiting for peer to accept...")
	
	status := make([]byte, 1)
	if _, err := io.ReadFull(conn, status); err != nil {
		fatal("connection dropped while waiting for peer", err)
	}
	if status[0] == 0x00 {
		fatal("connection rejected by peer", nil)
	}

	fmt.Println("  [VEIL] peer accepted! connection established.")
	handleSession(conn, aead, peerAddress)
	fmt.Println("  [VEIL] session closed.")
}

// performHandshake exchanges X25519 public keys, verifies identities, and derives a 32-byte shared secret
func performHandshake(conn net.Conn, isServer bool, myIdentity ed25519.PrivateKey) (string, cipher.AEAD, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate ecdh key: %w", err)
	}
	pub := priv.PublicKey().Bytes()

	myEdPub := myIdentity.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(myIdentity, pub)
	
	payload := append(pub, myEdPub...)
	payload = append(payload, signature...)

	peerPayload := make([]byte, 128)
	
	if isServer {
		if _, err := io.ReadFull(conn, peerPayload); err != nil {
			return "", nil, fmt.Errorf("failed to read peer payload: %w", err)
		}
		if _, err := conn.Write(payload); err != nil {
			return "", nil, fmt.Errorf("failed to send payload: %w", err)
		}
	} else {
		if _, err := conn.Write(payload); err != nil {
			return "", nil, fmt.Errorf("failed to send payload: %w", err)
		}
		if _, err := io.ReadFull(conn, peerPayload); err != nil {
			return "", nil, fmt.Errorf("failed to read peer payload: %w", err)
		}
	}

	peerX25519Pub := peerPayload[0:32]
	peerEdPub := peerPayload[32:64]
	peerSig := peerPayload[64:128]

	if !ed25519.Verify(ed25519.PublicKey(peerEdPub), peerX25519Pub, peerSig) {
		return "", nil, fmt.Errorf("invalid identity signature from peer")
	}

	peerKey, err := ecdh.X25519().NewPublicKey(peerX25519Pub)
	if err != nil {
		return "", nil, fmt.Errorf("invalid peer public key: %w", err)
	}

	secret, err := priv.ECDH(peerKey)
	if err != nil {
		return "", nil, fmt.Errorf("ecdh failed: %w", err)
	}

	hash := sha256.Sum256(secret)
	aead, err := chacha20poly1305.NewX(hash[:])
	if err != nil {
		return "", nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	peerAddress := torutil.OnionServiceIDFromV3PublicKey(torutil_ed25519.PublicKey(peerEdPub))

	return peerAddress, aead, nil
}

// -------------------------------------------------------------------------------------
// BUBBLE TEA USER INTERFACE
// -------------------------------------------------------------------------------------

type chatMsg struct {
	sender  string
	content string
}

type uiModel struct {
	viewport    viewport.Model
	textarea    textarea.Model
	messages    []string
	conn        net.Conn
	aead        cipher.AEAD
	peerAddress string
	err         error
}

func initialModel(conn net.Conn, aead cipher.AEAD, peerAddress string) uiModel {
	ta := textarea.New()
	ta.Placeholder = "Send an encrypted message..."
	ta.Focus()
	ta.Prompt = "┃ "
	ta.CharLimit = 4096
	ta.SetWidth(80)
	ta.SetHeight(3)

	ta.FocusedStyle.CursorLine = lipgloss.NewStyle() // Remove background color from cursor line
	ta.ShowLineNumbers = false
	ta.KeyMap.InsertNewline.SetEnabled(false) // Enter sends the message, Shift+Enter for newline

	vp := viewport.New(80, 20)
	vp.SetContent(infoStyle.Render("E2EE Session established with " + peerAddress + ".onion"))

	return uiModel{
		textarea:    ta,
		viewport:    vp,
		messages:    []string{},
		conn:        conn,
		aead:        aead,
		peerAddress: peerAddress,
	}
}

func (m uiModel) Init() tea.Cmd {
	return textarea.Blink
}

func (m uiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		tiCmd tea.Cmd
		vpCmd tea.Cmd
	)

	m.textarea, tiCmd = m.textarea.Update(msg)
	m.viewport, vpCmd = m.viewport.Update(msg)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit
		case tea.KeyEnter:
			content := strings.TrimSpace(m.textarea.Value())
			if content == "" {
				return m, nil
			}

			// 1. Encrypt and Send
			plaintext := []byte(content)
			nonce := make([]byte, m.aead.NonceSize())
			if _, err := io.ReadFull(rand.Reader, nonce); err == nil {
				ciphertext := m.aead.Seal(nil, nonce, plaintext, nil)
				frame := append(nonce, ciphertext...)
				
				lenBuf := make([]byte, 2)
				binary.BigEndian.PutUint16(lenBuf, uint16(len(frame)))
				
				m.conn.Write(lenBuf)
				m.conn.Write(frame)
			}

			// 2. Render locally
			m.messages = append(m.messages, myMsgStyle.Render("YOU: ")+content)
			m.viewport.SetContent(strings.Join(m.messages, "\n"))
			m.textarea.Reset()
			m.viewport.GotoBottom()
		}

	// Handle incoming messages from the secureReader background thread
	case chatMsg:
		m.messages = append(m.messages, peerMsgStyle.Render("PEER: ")+msg.content)
		m.viewport.SetContent(strings.Join(m.messages, "\n"))
		m.viewport.GotoBottom()
		return m, nil

	case error:
		m.err = msg
		return m, nil

	// Handle window resizing
	case tea.WindowSizeMsg:
		headerHeight := 1
		footerHeight := m.textarea.Height() + 1
		verticalMarginHeight := headerHeight + footerHeight

		m.viewport.Width = msg.Width
		m.viewport.Height = msg.Height - verticalMarginHeight
		m.textarea.SetWidth(msg.Width)
	}

	return m, tea.Batch(tiCmd, vpCmd)
}

func (m uiModel) View() string {
	header := titleStyle.Render(fmt.Sprintf("Veil Encrypted Chat | %s.onion", m.peerAddress))
	return fmt.Sprintf("%s\n%s\n\n%s", header, m.viewport.View(), m.textarea.View())
}

// handleSession starts the BubbleTea UI and the background reader
func handleSession(conn net.Conn, aead cipher.AEAD, peerAddress string) {
	p := tea.NewProgram(initialModel(conn, aead, peerAddress), tea.WithAltScreen())

	// Start background reader that pushes messages to the UI thread
	go secureReader(conn, aead, p)

	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
}

// secureReader continuously reads framed ciphertext, decrypts it, and pushes it to BubbleTea
func secureReader(conn net.Conn, aead cipher.AEAD, p *tea.Program) {
	lenBuf := make([]byte, 2)
	for {
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			p.Send(chatMsg{sender: "SYSTEM", content: infoStyle.Render("[Connection dropped by peer]")})
			return
		}
		
		msgLen := binary.BigEndian.Uint16(lenBuf)
		if msgLen == 0 {
			continue
		}

		cipherText := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, cipherText); err != nil {
			p.Send(chatMsg{sender: "SYSTEM", content: infoStyle.Render("[Failed to read message]")})
			return
		}

		if len(cipherText) < aead.NonceSize() {
			continue
		}
		
		nonce := cipherText[:aead.NonceSize()]
		actualCiphertext := cipherText[aead.NonceSize():]
		
		plaintext, err := aead.Open(nil, nonce, actualCiphertext, nil)
		if err != nil {
			p.Send(chatMsg{sender: "SYSTEM", content: infoStyle.Render("[Decryption failed - tampering detected?]")})
			continue
		}
		
		p.Send(chatMsg{sender: "PEER", content: string(plaintext)})
	}
}

// torDataDir returns the path where Tor stores its state data.
func torDataDir(isListener bool) string {
	suffix := "connect"
	if isListener {
		suffix = "listen"
	}
	
	home, err := os.UserHomeDir()
	if err != nil {
		return ".veil-tor-data-" + suffix
	}
	return home + "/.veil/tor-" + suffix
}

func fatal(msg string, err error) {
	fmt.Printf("\n  [ERROR] %s\n", msg)
	if err != nil {
		fmt.Printf("          %v\n\n", err)
	}
	os.Exit(1)
}

func printBanner() {
	fmt.Println()
	fmt.Println("  ██╗   ██╗███████╗██╗██╗     ")
	fmt.Println("  ██║   ██║██╔════╝██║██║     ")
	fmt.Println("  ██║   ██║█████╗  ██║██║     ")
	fmt.Println("  ╚██╗ ██╔╝██╔══╝  ██║██║     ")
	fmt.Println("   ╚████╔╝ ███████╗██║███████╗")
	fmt.Println("    ╚═══╝  ╚══════╝╚═╝╚══════╝")
	fmt.Println()
	fmt.Println("  ephemeral. encrypted. untraced.")
	fmt.Println()
	fmt.Println("────────────────────────────────────────────────────────────────")
	fmt.Println()
}
