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

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
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
	titleStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFDF5")).Background(lipgloss.Color("#6124DF")).Padding(0, 1).Bold(true)
	peerMsgStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
	myMsgStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)
	infoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Italic(true)
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	promptStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true)
)

// App States
type appState int

const (
	StateMainMenu appState = iota
	StateInputAddress
	StateLoading
	StatePrompt
	StateChat
	StateFatalError
)

// List Item
type menuItem string

func (i menuItem) Title() string       { return string(i) }
func (i menuItem) Description() string { return "" }
func (i menuItem) FilterValue() string { return string(i) }

// Async Messages
type torStartedMsg struct{ tor *tor.Tor }
type onionCreatedMsg struct{ onion *tor.OnionService }
type incomingConnectionMsg struct {
	conn        net.Conn
	aead        cipher.AEAD
	peerAddress string
}
type connectedMsg struct {
	conn        net.Conn
	aead        cipher.AEAD
	peerAddress string
}
type fatalErrorMsg struct {
	err     error
	context string
}

type chatMsg struct {
	content string
	system  bool
	dropped bool
}

type chatStream struct {
	ch <-chan chatMsg
}

// -------------------------------------------------------------------------------------
// CORE UI MODEL
// -------------------------------------------------------------------------------------

type uiModel struct {
	state appState

	// Cryptography & Network
	isServer    bool
	myIdentity  ed25519.PrivateKey
	t           *tor.Tor
	onion       *tor.OnionService
	conn        net.Conn
	aead        cipher.AEAD
	peerAddress string
	chatSub     chatStream

	// UI Components
	list       list.Model
	spinner    spinner.Model
	textinput  textinput.Model
	viewport   viewport.Model
	textarea   textarea.Model
	loadingMsg string
	fatalError string
	messages   []string
}

func initialModel(privateKey ed25519.PrivateKey) uiModel {
	// Main Menu List
	items := []list.Item{menuItem("Host a Chat (Listen)"), menuItem("Join a Chat (Connect)")}
	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Veil - Ephemeral Encrypted Chat"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)

	// Address Input
	ti := textinput.New()
	ti.Placeholder = "Enter target .onion address..."
	ti.Focus()
	ti.CharLimit = 156
	ti.Width = 60

	// Spinner
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	// Chat UI
	ta := textarea.New()
	ta.Placeholder = "Send an encrypted message..."
	ta.Focus()
	ta.Prompt = "┃ "
	ta.CharLimit = 4096
	ta.SetHeight(3)
	ta.FocusedStyle.CursorLine = lipgloss.NewStyle()
	ta.ShowLineNumbers = false
	ta.KeyMap.InsertNewline.SetEnabled(false)

	vp := viewport.New(80, 20)

	return uiModel{
		state:      StateMainMenu,
		myIdentity: privateKey,
		list:       l,
		spinner:    s,
		textinput:  ti,
		textarea:   ta,
		viewport:   vp,
		messages:   []string{},
	}
}

func (m uiModel) Init() tea.Cmd {
	// If CLI flags were provided, we bypass the main menu and instantly start loading
	if m.state == StateLoading {
		return tea.Batch(m.spinner.Tick, startTorCmd(m.isServer))
	}
	return nil
}

func (m uiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Global keybinds
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			if m.t != nil {
				m.t.Close()
			}
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.list.SetSize(msg.Width, msg.Height)
		m.textinput.Width = msg.Width - 4

		headerHeight := 1
		footerHeight := m.textarea.Height() + 1
		m.viewport.Width = msg.Width
		m.viewport.Height = msg.Height - (headerHeight + footerHeight)
		m.textarea.SetWidth(msg.Width)
	}

	// State-machine updates
	switch m.state {

	case StateMainMenu:
		switch msg := msg.(type) {
		case tea.KeyMsg:
			if msg.Type == tea.KeyEnter {
				i, ok := m.list.SelectedItem().(menuItem)
				if ok && i == "Host a Chat (Listen)" {
					m.isServer = true
					m.state = StateLoading
					m.loadingMsg = "Starting Tor daemon (may take 30-60s)..."
					return m, tea.Batch(m.spinner.Tick, startTorCmd(true))
				} else if ok && i == "Join a Chat (Connect)" {
					m.isServer = false
					m.state = StateInputAddress
					return m, nil
				}
			}
		}
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd

	case StateInputAddress:
		switch msg := msg.(type) {
		case tea.KeyMsg:
			if msg.Type == tea.KeyEnter {
				m.peerAddress = strings.TrimSuffix(strings.TrimSpace(m.textinput.Value()), ".onion")
				if m.peerAddress != "" {
					m.state = StateLoading
					m.loadingMsg = "Starting Tor daemon (may take 30-60s)..."
					return m, tea.Batch(m.spinner.Tick, startTorCmd(false))
				}
			} else if msg.Type == tea.KeyEsc {
				m.state = StateMainMenu
				return m, nil
			}
		}
		var cmd tea.Cmd
		m.textinput, cmd = m.textinput.Update(msg)
		return m, cmd

	case StateLoading:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)

		switch msg := msg.(type) {
		case torStartedMsg:
			m.t = msg.tor
			if m.isServer {
				m.loadingMsg = "Creating Onion Service..."
				return m, tea.Batch(cmd, createOnionCmd(m.t, m.myIdentity))
			} else {
				m.loadingMsg = "Connecting to " + m.peerAddress + ".onion..."
				return m, tea.Batch(cmd, dialPeerCmd(m.t, m.peerAddress, m.myIdentity))
			}
		case onionCreatedMsg:
			m.onion = msg.onion
			m.loadingMsg = "Listening at " + msg.onion.ID + ".onion\nWaiting for connections..."
			return m, tea.Batch(cmd, acceptConnectionCmd(msg.onion, m.myIdentity))
		case incomingConnectionMsg:
			m.conn = msg.conn
			m.aead = msg.aead
			m.peerAddress = msg.peerAddress
			m.state = StatePrompt
			return m, cmd
		case connectedMsg:
			m.conn = msg.conn
			m.aead = msg.aead
			m.peerAddress = msg.peerAddress
			m.state = StateChat
			m.viewport.SetContent(infoStyle.Render("E2EE Session established with " + m.peerAddress + ".onion"))
			m.chatSub = startReader(m.conn, m.aead)
			return m, tea.Batch(cmd, waitForChatMsg(m.chatSub), textarea.Blink)
		case fatalErrorMsg:
			m.state = StateFatalError
			m.fatalError = fmt.Sprintf("%s\n%v", msg.context, msg.err)
			return m, nil
		}
		return m, cmd

	case StatePrompt:
		switch msg := msg.(type) {
		case tea.KeyMsg:
			val := strings.ToLower(msg.String())
			if val == "y" {
				m.conn.Write([]byte{0x01})
				m.state = StateChat
				m.viewport.SetContent(infoStyle.Render("E2EE Session established with " + m.peerAddress + ".onion"))
				m.chatSub = startReader(m.conn, m.aead)
				return m, tea.Batch(waitForChatMsg(m.chatSub), textarea.Blink)
			} else if val == "n" || msg.Type == tea.KeyEsc {
				m.conn.Write([]byte{0x00})
				m.conn.Close()
				m.state = StateLoading
				m.loadingMsg = "Connection rejected.\nListening at " + m.onion.ID + ".onion\nWaiting for connections..."
				return m, tea.Batch(m.spinner.Tick, acceptConnectionCmd(m.onion, m.myIdentity))
			}
		}
		return m, nil

	case StateChat:
		var (
			tiCmd tea.Cmd
			vpCmd tea.Cmd
		)
		m.textarea, tiCmd = m.textarea.Update(msg)
		m.viewport, vpCmd = m.viewport.Update(msg)

		switch msg := msg.(type) {
		case tea.KeyMsg:
			if msg.Type == tea.KeyEnter {
				content := strings.TrimSpace(m.textarea.Value())
				if content == "" {
					return m, nil
				}

				// Encrypt & send
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

				m.messages = append(m.messages, myMsgStyle.Render("YOU: ")+content)
				m.viewport.SetContent(strings.Join(m.messages, "\n"))
				m.textarea.Reset()
				m.viewport.GotoBottom()
			}
		case chatMsg:
			if msg.system {
				m.messages = append(m.messages, infoStyle.Render(msg.content))
			} else {
				m.messages = append(m.messages, peerMsgStyle.Render("PEER: ")+msg.content)
			}
			m.viewport.SetContent(strings.Join(m.messages, "\n"))
			m.viewport.GotoBottom()
			if !msg.dropped {
				return m, tea.Batch(tiCmd, vpCmd, waitForChatMsg(m.chatSub))
			}
			return m, tea.Batch(tiCmd, vpCmd)
		}
		return m, tea.Batch(tiCmd, vpCmd)

	case StateFatalError:
		switch msg := msg.(type) {
		case tea.KeyMsg:
			if msg.Type == tea.KeyEsc {
				if m.t != nil {
					m.t.Close()
					m.t = nil
				}
				m.state = StateMainMenu
				return m, nil
			}
		}
	}

	return m, nil
}

func (m uiModel) View() string {
	switch m.state {
	case StateMainMenu:
		return m.list.View()
	case StateInputAddress:
		return fmt.Sprintf("Enter Target Onion Address:\n\n%s\n\n(esc to cancel)", m.textinput.View())
	case StateLoading:
		return fmt.Sprintf("\n %s %s\n", m.spinner.View(), m.loadingMsg)
	case StatePrompt:
		return fmt.Sprintf("\n %s\n\n %s", promptStyle.Render("INCOMING CONNECTION FROM: "+m.peerAddress+".onion"), "Accept? (y/n)")
	case StateChat:
		header := titleStyle.Render(fmt.Sprintf("Veil Encrypted Chat | %s.onion", m.peerAddress))
		return fmt.Sprintf("%s\n%s\n\n%s", header, m.viewport.View(), m.textarea.View())
	case StateFatalError:
		return fmt.Sprintf("\n %s\n %s\n\n (esc to return to menu)", errorStyle.Render("[FATAL ERROR]"), m.fatalError)
	}
	return ""
}

// -------------------------------------------------------------------------------------
// BACKGROUND COMMANDS
// -------------------------------------------------------------------------------------

func startTorCmd(isServer bool) tea.Cmd {
	return func() tea.Msg {
		extractedExe := extractTor(isServer)
		torConf := &tor.StartConf{
			DataDir: torDataDir(isServer),
			ExePath: extractedExe,
			ExtraArgs: []string{
				"--quiet",
				"--Log", "notice file " + filepath.Join(torDataDir(isServer), "tor.log"),
			},
		}
		ctx := context.Background()

		t, err := tor.Start(ctx, torConf)
		if err != nil {
			return fatalErrorMsg{err: err, context: "Failed to start Tor daemon"}
		}
		return torStartedMsg{tor: t}
	}
}

func createOnionCmd(t *tor.Tor, privateKey ed25519.PrivateKey) tea.Cmd {
	return func() tea.Msg {
		listenCtx, listenCancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer listenCancel()

		onion, err := t.Listen(listenCtx, &tor.ListenConf{
			RemotePorts: []int{7777},
			Key:         privateKey,
			Version3:    true,
		})
		if err != nil {
			return fatalErrorMsg{err: err, context: "Failed to create Onion Service"}
		}
		return onionCreatedMsg{onion: onion}
	}
}

func acceptConnectionCmd(onion *tor.OnionService, privateKey ed25519.PrivateKey) tea.Cmd {
	return func() tea.Msg {
		conn, err := onion.Accept()
		if err != nil {
			return fatalErrorMsg{err: err, context: "Failed to accept connection"}
		}
		peerAddress, aead, err := performHandshake(conn, true, privateKey)
		if err != nil {
			conn.Close()
			return fatalErrorMsg{err: err, context: "Handshake failed"}
		}
		return incomingConnectionMsg{conn: conn, aead: aead, peerAddress: peerAddress}
	}
}

func dialPeerCmd(t *tor.Tor, targetAddress string, privateKey ed25519.PrivateKey) tea.Cmd {
	return func() tea.Msg {
		dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer dialCancel()

		dialer, err := t.Dialer(dialCtx, nil)
		if err != nil {
			return fatalErrorMsg{err: err, context: "Failed to get tor dialer"}
		}

		conn, err := dialer.DialContext(dialCtx, "tcp", targetAddress+".onion:7777")
		if err != nil {
			return fatalErrorMsg{err: err, context: "Connection failed"}
		}

		peerAddress, aead, err := performHandshake(conn, false, privateKey)
		if err != nil {
			conn.Close()
			return fatalErrorMsg{err: err, context: "Handshake failed"}
		}

		if peerAddress != targetAddress {
			conn.Close()
			return fatalErrorMsg{err: fmt.Errorf("expected %s, got %s", targetAddress, peerAddress), context: "MITM DETECTED!"}
		}

		status := make([]byte, 1)
		if _, err := io.ReadFull(conn, status); err != nil {
			conn.Close()
			return fatalErrorMsg{err: err, context: "Dropped while waiting for peer acceptance"}
		}
		if status[0] == 0x00 {
			conn.Close()
			return fatalErrorMsg{err: fmt.Errorf("Connection rejected"), context: "Peer rejected connection"}
		}

		return connectedMsg{conn: conn, aead: aead, peerAddress: peerAddress}
	}
}

func startReader(conn net.Conn, aead cipher.AEAD) chatStream {
	ch := make(chan chatMsg)
	go func() {
		lenBuf := make([]byte, 2)
		for {
			if _, err := io.ReadFull(conn, lenBuf); err != nil {
				ch <- chatMsg{content: "[Connection dropped by peer]", system: true, dropped: true}
				return
			}
			msgLen := binary.BigEndian.Uint16(lenBuf)
			if msgLen == 0 {
				continue
			}

			cipherText := make([]byte, msgLen)
			if _, err := io.ReadFull(conn, cipherText); err != nil {
				ch <- chatMsg{content: "[Failed to read message]", system: true, dropped: true}
				return
			}

			if len(cipherText) < aead.NonceSize() {
				continue
			}

			nonce := cipherText[:aead.NonceSize()]
			actualCiphertext := cipherText[aead.NonceSize():]

			plaintext, err := aead.Open(nil, nonce, actualCiphertext, nil)
			if err != nil {
				ch <- chatMsg{content: "[Decryption failed - tampering detected?]", system: true}
				continue
			}

			ch <- chatMsg{content: string(plaintext), system: false}
		}
	}()
	return chatStream{ch: ch}
}

func waitForChatMsg(sub chatStream) tea.Cmd {
	return func() tea.Msg {
		return <-sub.ch
	}
}

// -------------------------------------------------------------------------------------
// CORE LOGIC
// -------------------------------------------------------------------------------------

func main() {
	listenFlag := flag.Bool("listen", false, "Listen for incoming connections")
	connectFlag := flag.String("connect", "", "Connect to a peer's onion address")
	flag.Parse()

	// Step 1: Generate Identity
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("failed to generate keypair:", err)
		os.Exit(1)
	}

	m := initialModel(privateKey)

	// Hybrid Fast-Track: if flags were provided, bypass the Main Menu
	if *listenFlag {
		m.isServer = true
		m.state = StateLoading
		m.loadingMsg = "Starting Tor daemon (may take 30-60s)..."
	} else if *connectFlag != "" {
		m.isServer = false
		m.peerAddress = strings.TrimSuffix(*connectFlag, ".onion")
		m.state = StateLoading
		m.loadingMsg = "Starting Tor daemon (may take 30-60s)..."
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}
}

func extractTor(isListener bool) string {
	dataDir := torDataDir(isListener)
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return "" // Will crash later on start
	}
	exePath := filepath.Join(dataDir, "tor.exe")
	if _, err := os.Stat(exePath); os.IsNotExist(err) {
		os.WriteFile(exePath, torBinary, 0700)
	}
	return exePath
}

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
