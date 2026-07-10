package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/cretz/bine/tor"
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

	// Step 1: Generate Identity (We need this for both connecting and listening eventually)
	fmt.Println("  [VEIL] generating identity keypair...")
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("failed to generate keypair", err)
	}

	// Step 2: Start Tor Daemon
	fmt.Println("  [VEIL] starting tor daemon (may take 30-60s)...")
	torConf := &tor.StartConf{
		DataDir: torDataDir(*listenFlag),
		ExePath: `C:\Users\matti\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`,
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
		runDialer(t, *connectFlag)
	}
}

// runListener handles incoming connections
func runListener(t *tor.Tor, privateKey ed25519.PrivateKey) {
	// Create the Onion Service in Tor
	fmt.Println("  [VEIL] creating onion service...")
	listenCtx, listenCancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer listenCancel()

	// bine's t.Listen creates both the Tor hidden service AND the local TCP listener automatically!
	onion, err := t.Listen(listenCtx, &tor.ListenConf{
		RemotePorts: []int{7777}, // Port exposed on the .onion address
		Key:         privateKey,
		Version3:    true,
	})
	if err != nil {
		fatal("failed to create onion service", err)
	}
	defer onion.Close()

	fmt.Printf("\n  [VEIL] listening at: %s.onion\n\n", onion.ID)

	// onion implements net.Listener, so we can Accept() directly on it!
	for {
		conn, err := onion.Accept()
		if err != nil {
			fmt.Println("  [ERROR] failed to accept connection:", err)
			continue
		}
		
		fmt.Println("  [VEIL] incoming connection received!")
		
		handleSession(conn)
		
		fmt.Println("  [VEIL] session closed.")
		conn.Close()
	}
}

// runDialer connects to another Veil node
func runDialer(t *tor.Tor, targetAddress string) {
	fmt.Printf("  [VEIL] connecting to %s ...\n", targetAddress)
	
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer dialCancel()

	// tor.Dialer gives us a way to connect out through the Tor network
	dialer, err := t.Dialer(dialCtx, nil)
	if err != nil {
		fatal("failed to get tor dialer", err)
	}

	// Dial the remote onion address
	conn, err := dialer.DialContext(dialCtx, "tcp", targetAddress+":7777")
	if err != nil {
		fatal("connection failed", err)
	}
	defer conn.Close()

	fmt.Println("  [VEIL] connected successfully!")
	
	handleSession(conn)
	fmt.Println("  [VEIL] session closed.")
}

// handleSession wires up the standard input/output to the connection for a raw chat
func handleSession(conn net.Conn) {
	fmt.Println("────────────────────────────────────────────────────────────────")
	fmt.Println("  [VEIL] session established. type to chat.")
	fmt.Println("────────────────────────────────────────────────────────────────")
	
	// Start a goroutine to print incoming messages to the terminal
	go func() {
		_, err := io.Copy(os.Stdout, conn)
		if err != nil {
			fmt.Println("\n  [VEIL] connection dropped.")
		}
	}()

	// The main goroutine reads from your keyboard and sends it to the peer
	io.Copy(conn, os.Stdin)
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

// fatal prints a formatted error and exits.
func fatal(msg string, err error) {
	fmt.Printf("\n  [ERROR] %s\n", msg)
	fmt.Printf("          %v\n\n", err)
	os.Exit(1)
}

// printBanner prints the Veil ASCII art header.
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
