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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
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

// -------------------------------------------------------------------------------------
// STYLES
// -------------------------------------------------------------------------------------

var (
	titleStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFDF5")).Background(lipgloss.Color("#6124DF")).Padding(0, 1).Bold(true)
	peerMsgStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
	myMsgStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)
	infoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Italic(true)
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	promptStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true)
	cmdStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("75")).Italic(true)
	focusedStyle = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("205"))
	dimStyle     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("241"))
)

// -------------------------------------------------------------------------------------
// APP STATES
// -------------------------------------------------------------------------------------

type appState int

const (
	StateMainMenu appState = iota
	StateInputAddress
	StateLoading
	StatePrompt
	StateChat
	StateFatalError
	StateCreatePassphrase
	StateEnterPassphrase
)

// -------------------------------------------------------------------------------------
// LIST ITEM TYPES
// -------------------------------------------------------------------------------------

// List Item
type menuItem string

func (i menuItem) Title() string       { return string(i) }
func (i menuItem) Description() string { return "" }
func (i menuItem) FilterValue() string { return string(i) }

// contactItem is used for the contacts list in the join screen.
type contactItem struct {
	name    string
	address string
}

func (i contactItem) Title() string       { return i.name }
func (i contactItem) Description() string { return i.address + ".onion" }
func (i contactItem) FilterValue() string { return i.name }

// Message type headers
const (
	MsgTypeChat         byte = 0x00
	MsgTypeFileOffer    byte = 0x01
	MsgTypeFileResponse byte = 0x02
	MsgTypeFileChunk    byte = 0x03
)

type FileOfferPayload struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type TransferState struct {
	FileName       string
	TotalSize      int64
	Transferred    int64
	StartTime      time.Time
	IsSending      bool
	OutputFile     *os.File
	ProgressMsgIdx int
}

type fileProgressMsg struct {
	transferred int64
	total       int64
	isSending   bool
	done        bool
	err         error
}

// -------------------------------------------------------------------------------------
// ASYNC MESSAGES
// -------------------------------------------------------------------------------------

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
	content      string
	system       bool
	dropped      bool
	fileOffer    *FileOfferPayload
	fileResponse *bool
	fileChunk    []byte
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
	peerNick    string // nickname if peer is a saved contact
	chatSub     chatStream

	// Contacts
	contacts      map[string]string // name → address
	joinFocusList bool              // true = navigating contacts, false = typing address

	// Passphrase state
	passphraseInput textinput.Model
	confirmMode     bool
	tempPassphrase  string
	passphraseErr   string
	burnerMode      bool
	autoAccept      bool

	// File transfer state
	pendingOffer    *FileOfferPayload
	sendingFilePath string
	activeTransfer  *TransferState
	progressSub     chan fileProgressMsg

	// UI Components
	list         list.Model
	contactsList list.Model
	spinner      spinner.Model
	textinput    textinput.Model
	viewport     viewport.Model
	textarea     textarea.Model
	loadingMsg   string
	fatalError   string
	messages     []string
	windowWidth  int
	windowHeight int
}

func initialModel(contacts map[string]string) uiModel {
	// Main Menu
	items := []list.Item{menuItem("Host a Chat (Listen)"), menuItem("Join a Chat (Connect)")}
	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Veil — Ephemeral Encrypted Chat"
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)

	// Contacts list (pre-initialized as empty so WindowSizeMsg never hits a zero-value model)
	cl := list.New([]list.Item{}, list.NewDefaultDelegate(), 0, 0)
	cl.Title = "Saved Contacts"
	cl.SetShowStatusBar(false)
	cl.SetFilteringEnabled(false)

	// Address Input
	ti := textinput.New()
	ti.Placeholder = "Paste .onion address here..."
	ti.Focus()
	ti.CharLimit = 156
	ti.Width = 60

	// Passphrase Input
	pi := textinput.New()
	pi.Placeholder = "Password"
	pi.Focus()
	pi.EchoMode = textinput.EchoPassword
	pi.EchoCharacter = '*'
	pi.Width = 40

	// Spinner
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	// Chat UI
	ta := textarea.New()
	ta.Placeholder = "Send a message... (/add <name> to save contact, /remove <name> to delete)"
	ta.Focus()
	ta.Prompt = "┃ "
	ta.CharLimit = 4096
	ta.SetHeight(3)
	ta.FocusedStyle.CursorLine = lipgloss.NewStyle()
	ta.ShowLineNumbers = false
	ta.KeyMap.InsertNewline.SetEnabled(false)

	vp := viewport.New(80, 20)

	return uiModel{
		state:           StateMainMenu,
		contacts:        contacts,
		passphraseInput: pi,
		list:            l,
		contactsList:    cl,
		spinner:         s,
		textinput:       ti,
		textarea:        ta,
		viewport:        vp,
		messages:        []string{},
	}
}

// buildContactsList creates a list.Model from the current contacts map for the join screen.
func buildContactsList(contacts map[string]string, w, h int) list.Model {
	names := make([]string, 0, len(contacts))
	for name := range contacts {
		names = append(names, name)
	}
	sort.Strings(names)

	items := make([]list.Item, 0, len(names))
	for _, name := range names {
		items = append(items, contactItem{name: name, address: contacts[name]})
	}

	cl := list.New(items, list.NewDefaultDelegate(), w, h)
	cl.Title = "Saved Contacts"
	cl.SetShowStatusBar(false)
	cl.SetFilteringEnabled(false)
	return cl
}

func (m uiModel) Init() tea.Cmd {
	if m.state == StateLoading {
		return tea.Batch(m.spinner.Tick, startTorCmd(m.isServer))
	}
	if m.state == StateCreatePassphrase || m.state == StateEnterPassphrase {
		return textinput.Blink
	}
	return nil
}

func (m uiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Global keybinds & window resize
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			if m.t != nil {
				m.t.Close()
			}
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.windowWidth = msg.Width
		m.windowHeight = msg.Height

		m.list.SetSize(msg.Width, msg.Height)
		m.textinput.Width = msg.Width - 4

		headerHeight := 1
		footerHeight := m.textarea.Height() + 1
		m.viewport.Width = msg.Width
		m.viewport.Height = msg.Height - (headerHeight + footerHeight)
		m.textarea.SetWidth(msg.Width)

		// Resize contacts list: half height for the join screen
		contactsH := msg.Height/2 - 4
		if contactsH < 3 {
			contactsH = 3
		}
		m.contactsList.SetSize(msg.Width-4, contactsH)
	}

	// State-machine updates
	switch m.state {

	case StateCreatePassphrase:
		var cmd tea.Cmd
		m.passphraseInput, cmd = m.passphraseInput.Update(msg)
		switch msg := msg.(type) {
		case tea.KeyMsg:
			if msg.Type == tea.KeyEnter {
				val := m.passphraseInput.Value()
				m.passphraseInput.SetValue("")
				if val == "" {
					return m, nil
				}
				if !m.confirmMode {
					m.tempPassphrase = val
					m.confirmMode = true
					m.passphraseInput.Placeholder = "Confirm Password"
					m.passphraseErr = ""
					return m, nil
				} else {
					if val == m.tempPassphrase {
						_, priv, err := ed25519.GenerateKey(rand.Reader)
						if err != nil {
							m.state = StateFatalError
							m.fatalError = "Failed to generate identity: " + err.Error()
							return m, nil
						}
						encrypted, err := encryptIdentity(priv, val)
						if err != nil {
							m.state = StateFatalError
							m.fatalError = "Failed to encrypt identity: " + err.Error()
							return m, nil
						}
						keyPath := identityKeyPath()
						if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
							m.state = StateFatalError
							m.fatalError = "Failed to create config dir: " + err.Error()
							return m, nil
						}
						if err := os.WriteFile(keyPath, encrypted, 0600); err != nil {
							m.state = StateFatalError
							m.fatalError = "Failed to save identity: " + err.Error()
							return m, nil
						}
						m.myIdentity = priv
						m.confirmMode = false
						m.tempPassphrase = ""
						m.passphraseErr = ""
						if m.isServer || m.peerAddress != "" {
							m.state = StateLoading
							return m, tea.Batch(m.spinner.Tick, startTorCmd(m.isServer))
						}
						m.state = StateMainMenu
						return m, nil
					} else {
						m.passphraseErr = "Passwords do not match. Try again."
						m.confirmMode = false
						m.tempPassphrase = ""
						m.passphraseInput.Placeholder = "Password"
						return m, nil
					}
				}
			}
		}
		return m, cmd

	case StateEnterPassphrase:
		var cmd tea.Cmd
		m.passphraseInput, cmd = m.passphraseInput.Update(msg)
		switch msg := msg.(type) {
		case tea.KeyMsg:
			if msg.Type == tea.KeyEnter {
				val := m.passphraseInput.Value()
				m.passphraseInput.SetValue("")
				if val == "" {
					return m, nil
				}
				keyPath := identityKeyPath()
				encryptedData, err := os.ReadFile(keyPath)
				if err != nil {
					m.state = StateFatalError
					m.fatalError = "Failed to read identity: " + err.Error()
					return m, nil
				}
				priv, err := decryptIdentity(encryptedData, val)
				if err != nil {
					m.passphraseErr = "Incorrect passphrase. Please try again."
					return m, nil
				}
				m.myIdentity = priv
				m.passphraseErr = ""
				if m.isServer || m.peerAddress != "" {
					m.state = StateLoading
					return m, tea.Batch(m.spinner.Tick, startTorCmd(m.isServer))
				}
				m.state = StateMainMenu
				return m, nil
			}
		}
		return m, cmd

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
					// Rebuild contacts list with current window size
					contactsH := m.windowHeight/2 - 4
					if contactsH < 3 {
						contactsH = 3
					}
					m.contactsList = buildContactsList(m.contacts, m.windowWidth-4, contactsH)
					// Default focus: list if contacts exist, input otherwise
					m.joinFocusList = len(m.contacts) > 0
					m.textinput.SetValue("")
					return m, nil
				}
			}
		}
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd

	// ── ADDRESS / CONTACTS INPUT ────────────────────────────────────────────────
	case StateInputAddress:
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.Type {
			case tea.KeyEsc:
				m.state = StateMainMenu
				return m, nil

			case tea.KeyTab:
				if len(m.contacts) > 0 {
					m.joinFocusList = !m.joinFocusList
					return m, nil
				}

			case tea.KeyEnter:
				var targetAddress string
				if m.joinFocusList {
					if item, ok := m.contactsList.SelectedItem().(contactItem); ok {
						targetAddress = item.address
					}
				} else {
					targetAddress = strings.TrimSuffix(strings.TrimSpace(m.textinput.Value()), ".onion")
				}
				if targetAddress != "" {
					m.peerAddress = targetAddress
					m.state = StateLoading
					m.loadingMsg = "Starting Tor daemon (may take 30-60s)..."
					return m, tea.Batch(m.spinner.Tick, startTorCmd(false))
				}
			}
		}
		// Route key events to the focused widget
		if m.joinFocusList {
			var cmd tea.Cmd
			m.contactsList, cmd = m.contactsList.Update(msg)
			return m, cmd
		}
		var cmd tea.Cmd
		m.textinput, cmd = m.textinput.Update(msg)
		return m, cmd

	// ── LOADING ─────────────────────────────────────────────────────────────────
	case StateLoading:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)

		switch msg := msg.(type) {
		case torStartedMsg:
			m.t = msg.tor
			if m.isServer {
				m.loadingMsg = "Creating Onion Service..."
				return m, tea.Batch(cmd, createOnionCmd(m.t, m.myIdentity))
			}
			m.loadingMsg = "Connecting to " + m.peerAddress + ".onion..."
			return m, tea.Batch(cmd, dialPeerCmd(m.t, m.peerAddress, m.myIdentity))

		case onionCreatedMsg:
			m.onion = msg.onion
			m.loadingMsg = "Listening at " + msg.onion.ID + ".onion\nWaiting for connections..."
			return m, tea.Batch(cmd, acceptConnectionCmd(msg.onion, m.myIdentity))

		case incomingConnectionMsg:
			m.conn = msg.conn
			m.aead = msg.aead
			m.peerAddress = msg.peerAddress
			m.peerNick = LookupNickname(m.contacts, msg.peerAddress)
			if m.autoAccept && m.peerNick != "" {
				m.conn.Write([]byte{0x01})
				m.state = StateChat
				m.messages = []string{}
				m.viewport.SetContent(infoStyle.Render("Auto-accepted connection from " + m.peerDisplayName() + "."))
				m.chatSub = startReader(m.conn, m.aead)
				return m, tea.Batch(cmd, waitForChatMsg(m.chatSub), textarea.Blink)
			}
			m.state = StatePrompt
			return m, cmd

		case connectedMsg:
			m.conn = msg.conn
			m.aead = msg.aead
			m.peerAddress = msg.peerAddress
			m.peerNick = LookupNickname(m.contacts, msg.peerAddress)
			m.state = StateChat
			m.messages = []string{}
			m.viewport.SetContent(infoStyle.Render("E2EE session established with " + m.peerDisplayName() + ". Type /add <name> to save this contact."))
			m.chatSub = startReader(m.conn, m.aead)
			return m, tea.Batch(cmd, waitForChatMsg(m.chatSub), textarea.Blink)

		case fatalErrorMsg:
			m.state = StateFatalError
			m.fatalError = fmt.Sprintf("%s\n%v", msg.context, msg.err)
			return m, nil
		}
		return m, cmd

	// ── ACCEPT / REJECT PROMPT ──────────────────────────────────────────────────
	case StatePrompt:
		switch msg := msg.(type) {
		case tea.KeyMsg:
			val := strings.ToLower(msg.String())
			if val == "y" {
				m.conn.Write([]byte{0x01})
				m.state = StateChat
				m.messages = []string{}
				m.viewport.SetContent(infoStyle.Render("E2EE session established with " + m.peerDisplayName() + ". Type /add <name> to save this contact."))
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

	// ── CHAT ────────────────────────────────────────────────────────────────────
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
				m.textarea.Reset()
				if content == "" {
					return m, tea.Batch(tiCmd, vpCmd)
				}

				// ── Slash commands ─────────────────────────────────────────────
				if content == "/help" {
					helpText := "Available Chat Commands:\n" +
						"  /help          Show this help message\n" +
						"  /add <name>    Save current peer to contacts\n" +
						"  /remove <name> Remove a contact by nickname\n" +
						"  /send <path>   Transfer a file to active peer\n" +
						"  /accept        Accept an incoming file offer\n" +
						"  /reject        Reject an incoming file offer"
					m.appendSystem(helpText)
					m.viewport.SetContent(strings.Join(m.messages, "\n"))
					m.viewport.GotoBottom()
					return m, tea.Batch(tiCmd, vpCmd)
				}

				if strings.HasPrefix(content, "/add ") {
					nickname := strings.TrimSpace(strings.TrimPrefix(content, "/add "))
					if nickname == "" {
						m.appendSystem("Usage: /add <nickname>")
					} else if err := AddContact(nickname, m.peerAddress); err != nil {
						m.appendSystem("Error saving contact: " + err.Error())
					} else {
						m.contacts[strings.ToLower(nickname)] = m.peerAddress
						m.peerNick = nickname
						m.appendSystem(cmdStyle.Render("✓ Contact saved: \"" + nickname + "\" → " + m.peerAddress + ".onion"))
					}
					m.viewport.SetContent(strings.Join(m.messages, "\n"))
					m.viewport.GotoBottom()
					return m, tea.Batch(tiCmd, vpCmd)
				}

				if strings.HasPrefix(content, "/remove ") {
					nickname := strings.TrimSpace(strings.TrimPrefix(content, "/remove "))
					if nickname == "" {
						m.appendSystem("Usage: /remove <nickname>")
					} else if err := RemoveContact(nickname); err != nil {
						m.appendSystem("Error: " + err.Error())
					} else {
						delete(m.contacts, strings.ToLower(nickname))
						if strings.EqualFold(m.peerNick, nickname) {
							m.peerNick = ""
						}
						m.appendSystem(cmdStyle.Render("✓ Contact removed: \"" + nickname + "\""))
					}
					m.viewport.SetContent(strings.Join(m.messages, "\n"))
					m.viewport.GotoBottom()
					return m, tea.Batch(tiCmd, vpCmd)
				}

				if strings.HasPrefix(content, "/send ") {
					filePath := strings.TrimSpace(strings.TrimPrefix(content, "/send "))
					filePath = strings.Trim(filePath, "\"'")
					if filePath == "" {
						m.appendSystem("Usage: /send <file_path>")
					} else if info, err := os.Stat(filePath); err != nil {
						m.appendSystem("Error: file not found or inaccessible: " + err.Error())
					} else if info.IsDir() {
						m.appendSystem("Error: specified path is a directory, not a file.")
					} else {
						m.sendingFilePath = filePath
						offer := FileOfferPayload{
							Name: filepath.Base(filePath),
							Size: info.Size(),
						}
						payload, _ := json.Marshal(offer)
						if err := sendFrame(m.conn, m.aead, MsgTypeFileOffer, payload); err != nil {
							m.appendSystem("Failed to send file offer: " + err.Error())
						} else {
							m.appendSystem(cmdStyle.Render(fmt.Sprintf("Sent file offer: \"%s\" (%s). Waiting for peer...", offer.Name, formatSize(offer.Size))))
						}
					}
					m.viewport.SetContent(strings.Join(m.messages, "\n"))
					m.viewport.GotoBottom()
					return m, tea.Batch(tiCmd, vpCmd)
				}

				if content == "/accept" {
					if m.pendingOffer == nil {
						m.appendSystem("No pending file offer to accept.")
					} else {
						home, _ := os.UserHomeDir()
						destDir := filepath.Join(home, "Downloads")
						os.MkdirAll(destDir, 0755)
						destPath := filepath.Join(destDir, m.pendingOffer.Name)

						f, err := os.Create(destPath)
						if err != nil {
							m.appendSystem("Error creating destination file: " + err.Error())
						} else {
							m.activeTransfer = &TransferState{
								FileName:    m.pendingOffer.Name,
								TotalSize:   m.pendingOffer.Size,
								Transferred: 0,
								StartTime:   time.Now(),
								IsSending:   false,
								OutputFile:  f,
							}
							sendFrame(m.conn, m.aead, MsgTypeFileResponse, []byte{0x01})
							m.appendSystem(cmdStyle.Render(fmt.Sprintf("Accepted file \"%s\". Receiving...", m.pendingOffer.Name)))
							progressLine := renderProgressBar(0, m.pendingOffer.Size, time.Now(), false)
							m.messages = append(m.messages, progressLine)
							m.activeTransfer.ProgressMsgIdx = len(m.messages) - 1
							m.pendingOffer = nil
						}
					}
					m.viewport.SetContent(strings.Join(m.messages, "\n"))
					m.viewport.GotoBottom()
					return m, tea.Batch(tiCmd, vpCmd)
				}

				if content == "/reject" {
					if m.pendingOffer == nil {
						m.appendSystem("No pending file offer to reject.")
					} else {
						sendFrame(m.conn, m.aead, MsgTypeFileResponse, []byte{0x00})
						m.appendSystem(cmdStyle.Render(fmt.Sprintf("Rejected file offer for \"%s\".", m.pendingOffer.Name)))
						m.pendingOffer = nil
					}
					m.viewport.SetContent(strings.Join(m.messages, "\n"))
					m.viewport.GotoBottom()
					return m, tea.Batch(tiCmd, vpCmd)
				}

				// ── Regular message — encrypt & send ───────────────────────────
				if err := sendFrame(m.conn, m.aead, MsgTypeChat, []byte(content)); err != nil {
					m.appendSystem("Failed to send message: " + err.Error())
				} else {
					m.messages = append(m.messages, myMsgStyle.Render("YOU: ")+content)
				}
				m.viewport.SetContent(strings.Join(m.messages, "\n"))
				m.viewport.GotoBottom()
			}

		case fileProgressMsg:
			if m.activeTransfer != nil && m.activeTransfer.IsSending {
				if msg.err != nil {
					m.appendSystem("File upload error: " + msg.err.Error())
					m.activeTransfer = nil
				} else {
					m.activeTransfer.Transferred = msg.transferred
					pLine := renderProgressBar(msg.transferred, msg.total, m.activeTransfer.StartTime, true)
					if m.activeTransfer.ProgressMsgIdx < len(m.messages) {
						m.messages[m.activeTransfer.ProgressMsgIdx] = pLine
					}
					if msg.done {
						m.messages[m.activeTransfer.ProgressMsgIdx] = cmdStyle.Render(fmt.Sprintf("✓ File transfer complete: \"%s\" sent successfully.", m.activeTransfer.FileName))
						m.activeTransfer = nil
					} else {
						m.viewport.SetContent(strings.Join(m.messages, "\n"))
						m.viewport.GotoBottom()
						return m, tea.Batch(tiCmd, vpCmd, waitForProgressMsg(m.progressSub))
					}
				}
			}
			m.viewport.SetContent(strings.Join(m.messages, "\n"))
			m.viewport.GotoBottom()
			return m, tea.Batch(tiCmd, vpCmd)

		case chatMsg:
			if msg.fileOffer != nil {
				if m.autoAccept && m.peerNick != "" {
					home, _ := os.UserHomeDir()
					destDir := filepath.Join(home, "Downloads")
					os.MkdirAll(destDir, 0755)
					destPath := filepath.Join(destDir, msg.fileOffer.Name)

					f, err := os.Create(destPath)
					if err == nil {
						m.activeTransfer = &TransferState{
							FileName:    msg.fileOffer.Name,
							TotalSize:   msg.fileOffer.Size,
							Transferred: 0,
							StartTime:   time.Now(),
							IsSending:   false,
							OutputFile:  f,
						}
						sendFrame(m.conn, m.aead, MsgTypeFileResponse, []byte{0x01})
						m.appendSystem(cmdStyle.Render(fmt.Sprintf("Auto-accepted file \"%s\". Receiving...", msg.fileOffer.Name)))
						progressLine := renderProgressBar(0, msg.fileOffer.Size, time.Now(), false)
						m.messages = append(m.messages, progressLine)
						m.activeTransfer.ProgressMsgIdx = len(m.messages) - 1
					} else {
						m.appendSystem("Error creating file: " + err.Error())
					}
				} else {
					m.pendingOffer = msg.fileOffer
					m.appendSystem(promptStyle.Render(fmt.Sprintf("Incoming file offer: \"%s\" (%s). Type /accept or /reject.", msg.fileOffer.Name, formatSize(msg.fileOffer.Size))))
				}
			} else if msg.fileResponse != nil {
				if *msg.fileResponse {
					if m.sendingFilePath != "" {
						info, err := os.Stat(m.sendingFilePath)
						if err == nil {
							m.activeTransfer = &TransferState{
								FileName:    filepath.Base(m.sendingFilePath),
								TotalSize:   info.Size(),
								Transferred: 0,
								StartTime:   time.Now(),
								IsSending:   true,
							}
							m.appendSystem(cmdStyle.Render(fmt.Sprintf("Peer accepted \"%s\". Starting upload...", m.activeTransfer.FileName)))
							pLine := renderProgressBar(0, info.Size(), time.Now(), true)
							m.messages = append(m.messages, pLine)
							m.activeTransfer.ProgressMsgIdx = len(m.messages) - 1
							m.progressSub = make(chan fileProgressMsg, 100)
							sendCmd := sendFileChunksCmd(m.conn, m.aead, m.sendingFilePath, m.progressSub)
							m.viewport.SetContent(strings.Join(m.messages, "\n"))
							m.viewport.GotoBottom()
							return m, tea.Batch(tiCmd, vpCmd, sendCmd, waitForChatMsg(m.chatSub))
						}
					}
				} else {
					m.appendSystem(infoStyle.Render("Peer rejected file offer."))
					m.sendingFilePath = ""
				}
			} else if msg.fileChunk != nil {
				if m.activeTransfer != nil && !m.activeTransfer.IsSending && m.activeTransfer.OutputFile != nil {
					n, err := m.activeTransfer.OutputFile.Write(msg.fileChunk)
					if err != nil {
						m.appendSystem("File write error: " + err.Error())
						m.activeTransfer.OutputFile.Close()
						m.activeTransfer = nil
					} else {
						m.activeTransfer.Transferred += int64(n)
						pLine := renderProgressBar(m.activeTransfer.Transferred, m.activeTransfer.TotalSize, m.activeTransfer.StartTime, false)
						if m.activeTransfer.ProgressMsgIdx < len(m.messages) {
							m.messages[m.activeTransfer.ProgressMsgIdx] = pLine
						}
						if m.activeTransfer.Transferred >= m.activeTransfer.TotalSize {
							destPath := m.activeTransfer.OutputFile.Name()
							m.activeTransfer.OutputFile.Close()
							m.messages[m.activeTransfer.ProgressMsgIdx] = cmdStyle.Render(fmt.Sprintf("✓ File received: \"%s\" saved to %s", m.activeTransfer.FileName, destPath))
							m.activeTransfer = nil
						}
					}
				}
			} else if msg.system {
				m.appendSystem(msg.content)
			} else {
				m.messages = append(m.messages, peerMsgStyle.Render(m.peerDisplayName()+": ")+msg.content)
			}
			m.viewport.SetContent(strings.Join(m.messages, "\n"))
			m.viewport.GotoBottom()
			if !msg.dropped {
				return m, tea.Batch(tiCmd, vpCmd, waitForChatMsg(m.chatSub))
			}
			return m, tea.Batch(tiCmd, vpCmd)
		}
		return m, tea.Batch(tiCmd, vpCmd)

	// ── FATAL ERROR ─────────────────────────────────────────────────────────────
	case StateFatalError:
		if msg, ok := msg.(tea.KeyMsg); ok && msg.Type == tea.KeyEsc {
			if m.t != nil {
				m.t.Close()
				m.t = nil
			}
			m.state = StateMainMenu
			return m, nil
		}
	}

	return m, nil
}

// peerDisplayName returns the peer's nickname if known, otherwise their address.
func (m *uiModel) peerDisplayName() string {
	if m.peerNick != "" {
		return m.peerNick
	}
	return "PEER"
}

// appendSystem appends a styled system message to the chat log.
func (m *uiModel) appendSystem(msg string) {
	m.messages = append(m.messages, infoStyle.Render(msg))
}

func (m uiModel) View() string {
	switch m.state {

	case StateCreatePassphrase:
		prompt := "Create a master passphrase to secure your local identity:"
		if m.confirmMode {
			prompt = "Confirm master passphrase:"
		}
		errStr := ""
		if m.passphraseErr != "" {
			errStr = "\n  " + errorStyle.Render(m.passphraseErr) + "\n"
		}
		return fmt.Sprintf("\n  %s\n\n  %s\n%s", prompt, m.passphraseInput.View(), errStr)

	case StateEnterPassphrase:
		errStr := ""
		if m.passphraseErr != "" {
			errStr = "\n  " + errorStyle.Render(m.passphraseErr) + "\n"
		}
		return fmt.Sprintf("\n  Enter master passphrase to unlock your identity:\n\n  %s\n%s", m.passphraseInput.View(), errStr)

	case StateMainMenu:
		return m.list.View()

	case StateInputAddress:
		if len(m.contacts) > 0 {
			contactsBox := m.contactsList.View()
			inputBox := m.textinput.View()

			var cStyle, iStyle lipgloss.Style
			if m.joinFocusList {
				cStyle = focusedStyle
				iStyle = dimStyle
			} else {
				cStyle = dimStyle
				iStyle = focusedStyle
			}

			return fmt.Sprintf(
				"%s\n\n%s\n\n[Tab] to switch focus  •  [Enter] to connect  •  [Esc] back",
				cStyle.Render(contactsBox),
				iStyle.Render(inputBox),
			)
		}
		return fmt.Sprintf(
			"  Enter Target Onion Address\n\n  %s\n\n  [Enter] connect  •  [Esc] back",
			m.textinput.View(),
		)

	case StateLoading:
		return fmt.Sprintf("\n  %s %s\n", m.spinner.View(), m.loadingMsg)

	case StatePrompt:
		peerLabel := m.peerAddress + ".onion"
		if m.peerNick != "" {
			peerLabel = m.peerNick + " (" + m.peerAddress + ".onion)"
		}
		return fmt.Sprintf(
			"\n  %s\n\n  Accept? [y/n]",
			promptStyle.Render("INCOMING CONNECTION FROM: "+peerLabel),
		)

	case StateChat:
		peerLabel := m.peerAddress + ".onion"
		if m.peerNick != "" {
			peerLabel = m.peerNick + " (" + m.peerAddress + ".onion)"
		}
		header := titleStyle.Render("Veil  |  " + peerLabel)
		return fmt.Sprintf("%s\n%s\n\n%s", header, m.viewport.View(), m.textarea.View())

	case StateFatalError:
		return fmt.Sprintf(
			"\n  %s\n  %s\n\n  [Esc] return to menu",
			errorStyle.Render("[FATAL ERROR]"),
			m.fatalError,
		)
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
			return fatalErrorMsg{
				err:     fmt.Errorf("expected %s, got %s", targetAddress, peerAddress),
				context: "MITM DETECTED!",
			}
		}
		status := make([]byte, 1)
		if _, err := io.ReadFull(conn, status); err != nil {
			conn.Close()
			return fatalErrorMsg{err: err, context: "Dropped while waiting for peer acceptance"}
		}
		if status[0] == 0x00 {
			conn.Close()
			return fatalErrorMsg{err: fmt.Errorf("connection rejected by peer"), context: "Peer rejected connection"}
		}
		return connectedMsg{conn: conn, aead: aead, peerAddress: peerAddress}
	}
}

func sendFrame(conn net.Conn, aead cipher.AEAD, msgType byte, payload []byte) error {
	plaintext := make([]byte, 1+len(payload))
	plaintext[0] = msgType
	copy(plaintext[1:], payload)

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	frame := append(nonce, ciphertext...)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(frame)))
	if _, err := conn.Write(lenBuf); err != nil {
		return err
	}
	if _, err := conn.Write(frame); err != nil {
		return err
	}
	return nil
}

func formatSize(bytes int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func renderProgressBar(transferred, total int64, startTime time.Time, isSending bool) string {
	if total <= 0 {
		total = 1
	}
	if transferred < 0 {
		transferred = 0
	}

	pct := float64(transferred) / float64(total) * 100.0
	if math.IsNaN(pct) || pct < 0.0 {
		pct = 0.0
	}
	if pct > 100.0 {
		pct = 100.0
	}

	barLen := 20
	filled := int(pct / 100.0 * float64(barLen))
	if filled < 0 {
		filled = 0
	}
	if filled > barLen {
		filled = barLen
	}

	unfilled := barLen - filled
	if unfilled < 0 {
		unfilled = 0
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", unfilled)

	elapsed := time.Since(startTime).Seconds()
	var speed float64
	if elapsed > 0 {
		speed = float64(transferred) / elapsed
	}

	remainingBytes := total - transferred
	if remainingBytes < 0 {
		remainingBytes = 0
	}

	var etaSec int
	if speed > 0 && remainingBytes > 0 {
		etaSec = int(float64(remainingBytes) / speed)
	}

	direction := "Downloading"
	if isSending {
		direction = "Uploading"
	}

	return fmt.Sprintf("┃ [%s] %5.1f%% | %s / %s | %s/s | ETA %02d:%02d (%s)",
		bar, pct, formatSize(transferred), formatSize(total), formatSize(int64(speed)), etaSec/60, etaSec%60, direction)
}

func sendFileChunksCmd(conn net.Conn, aead cipher.AEAD, filePath string, ch chan fileProgressMsg) tea.Cmd {
	go func() {
		f, err := os.Open(filePath)
		if err != nil {
			ch <- fileProgressMsg{err: err}
			return
		}
		defer f.Close()

		info, err := f.Stat()
		if err != nil {
			ch <- fileProgressMsg{err: err}
			return
		}

		total := info.Size()
		buf := make([]byte, 32768)
		var sent int64

		for {
			n, readErr := f.Read(buf)
			if n > 0 {
				if err := sendFrame(conn, aead, MsgTypeFileChunk, buf[:n]); err != nil {
					ch <- fileProgressMsg{err: err}
					return
				}
				sent += int64(n)
				ch <- fileProgressMsg{transferred: sent, total: total, isSending: true, done: sent >= total}
			}
			if readErr != nil {
				if readErr == io.EOF {
					if sent < total {
						ch <- fileProgressMsg{transferred: total, total: total, isSending: true, done: true}
					}
				} else {
					ch <- fileProgressMsg{err: readErr}
				}
				break
			}
		}
	}()
	return waitForProgressMsg(ch)
}

func waitForProgressMsg(ch chan fileProgressMsg) tea.Cmd {
	return func() tea.Msg {
		return <-ch
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
				ch <- chatMsg{content: "[Decryption failed — tampering detected?]", system: true}
				continue
			}
			if len(plaintext) == 0 {
				continue
			}

			msgType := plaintext[0]
			payload := plaintext[1:]

			switch msgType {
			case MsgTypeChat:
				ch <- chatMsg{content: string(payload), system: false}

			case MsgTypeFileOffer:
				var offer FileOfferPayload
				if err := json.Unmarshal(payload, &offer); err == nil {
					ch <- chatMsg{fileOffer: &offer}
				}

			case MsgTypeFileResponse:
				if len(payload) > 0 {
					accepted := payload[0] == 0x01
					ch <- chatMsg{fileResponse: &accepted}
				}

			case MsgTypeFileChunk:
				ch <- chatMsg{fileChunk: payload}
			}
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
	burnerMode := flag.Bool("burner-mode", false, "Run in burner mode (random temporary identity)")
	autoAccept := flag.Bool("auto-accept", false, "Auto-accept connections and file transfers from saved contacts")

	flag.Usage = func() {
		banner := titleStyle.Render(" Veil — Ephemeral Encrypted P2P Messenger ")
		fmt.Printf("\n%s\n\n", banner)
		fmt.Println(promptStyle.Render("USAGE:"))
		fmt.Println("  veil [FLAGS]\n")
		fmt.Println(promptStyle.Render("FLAGS:"))
		fmt.Println("  --listen               Start Veil in host/listener mode")
		fmt.Println("  --connect <address>    Connect directly to a peer's .onion address")
		fmt.Println("  --burner-mode          Run with a throwaway keypair (no disk persistence)")
		fmt.Println("  --auto-accept          Auto-accept connections & files from contacts")
		fmt.Println("  --help, -h             Show this help menu\n")
		fmt.Println(infoStyle.Render("IN-CHAT COMMANDS:"))
		fmt.Println("  /help                  Show in-session help menu")
		fmt.Println("  /add <name>            Save current peer to contacts")
		fmt.Println("  /remove <name>         Remove a contact by nickname")
		fmt.Println("  /send <path>           Transfer a file to the active peer")
		fmt.Println("  /accept                Accept an incoming file transfer")
		fmt.Println("  /reject                Reject an incoming file transfer\n")
	}

	flag.Parse()

	// Load contacts from disk (non-fatal if missing)
	contacts, err := LoadContacts()
	if err != nil {
		fmt.Println("warning: could not load contacts:", err)
		contacts = map[string]string{}
	}

	m := initialModel(contacts)
	m.autoAccept = *autoAccept

	// CLI fast-track: bypass the Main Menu if flags are provided
	if *listenFlag {
		m.isServer = true
		m.state = StateLoading
		m.loadingMsg = "Starting Tor daemon (may take 30-60s)..."
	} else if *connectFlag != "" {
		if strings.HasPrefix(*connectFlag, "-") {
			fmt.Println("Error: --connect requires a target .onion address.")
			fmt.Println("Correct order: veil --auto-accept --connect <address>  OR  veil --connect <address> --auto-accept")
			os.Exit(1)
		}
		m.isServer = false
		m.peerAddress = strings.TrimSuffix(*connectFlag, ".onion")
		m.state = StateLoading
		m.loadingMsg = "Starting Tor daemon (may take 30-60s)..."
	}

	if *burnerMode {
		m.burnerMode = true
		// Generate random temporary identity keypair immediately
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Println("fatal: failed to generate burner keypair:", err)
			os.Exit(1)
		}
		m.myIdentity = privKey
		// Bypasses passphrase states, go directly to MainMenu (or StateLoading if CLI flags are active)
		if !*listenFlag && *connectFlag == "" {
			m.state = StateMainMenu
		}
	} else {
		// Standard mode: check if identity.key exists
		keyPath := identityKeyPath()
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			m.state = StateCreatePassphrase
		} else {
			m.state = StateEnterPassphrase
		}
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}

// -------------------------------------------------------------------------------------
// HELPERS
// -------------------------------------------------------------------------------------

func extractTor(isListener bool) string {
	dataDir := torDataDir(isListener)
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return ""
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

func identityKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".veil-identity.key"
	}
	return filepath.Join(home, ".veil", "identity.key")
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
