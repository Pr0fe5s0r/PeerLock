package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

func handleStream(s network.Stream) {
	log.Println("Got a new stream!")

	// Create a buffer stream for non blocking read and write.
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	go readData(rw)
	//go writeData(rw)

	// stream 's' will stay open until you close it (or the other side closes it).
}

func readData(rw *bufio.ReadWriter) {
	for {
		str, _ := rw.ReadString('\n')

		if str == "" {
			return
		}
		if str != "\n" {
			// Green console colour: 	\x1b[32m
			// Reset console colour: 	\x1b[0m
			fmt.Printf("\x1b[32m%s\x1b[0m> ", str)
		}

	}
}

func writeData(rw *bufio.ReadWriter, hash string) {
	//sendData := "Hello World"
	rw.WriteString(fmt.Sprintf("%s\n", hash))
	rw.Flush()
}

// func main() {
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()

// 	sourcePort := flag.Int("sp", 0, "Source port number")
// 	dest := flag.String("d", "", "Destination multiaddr string")
// 	help := flag.Bool("help", false, "Display help")
// 	debug := flag.Bool("debug", false, "Debug generates the same node ID on every execution")

// 	flag.Parse()

// 	if *help {
// 		fmt.Printf("This program demonstrates a simple p2p chat application using libp2p\n\n")
// 		fmt.Println("Usage: Run './chat -sp <SOURCE_PORT>' where <SOURCE_PORT> can be any port number.")
// 		fmt.Println("Now run './chat -d <MULTIADDR>' where <MULTIADDR> is multiaddress of previous listener host.")

// 		os.Exit(0)
// 	}

// 	// If debug is enabled, use a constant random source to generate the peer ID. Only useful for debugging,
// 	// off by default. Otherwise, it uses rand.Reader.
// 	var r io.Reader
// 	if *debug {
// 		// Use the port number as the randomness source.
// 		// This will always generate the same host ID on multiple executions, if the same port number is used.
// 		// Never do this in production code.
// 		r = mrand.New(mrand.NewSource(int64(*sourcePort)))
// 	} else {
// 		r = rand.Reader
// 	}

// 	h, err := makeHost(*sourcePort, r)
// 	if err != nil {
// 		log.Println(err)
// 		return
// 	}

// 	if *dest == "" {
// 		startPeer(ctx, h, handleStream)
// 	} else {
// 		rw, err := startPeerAndConnect(ctx, h, *dest)
// 		if err != nil {
// 			log.Println(err)
// 			return
// 		}

// 		// Create a thread to read and write data.
// 		go writeData(rw)
// 		go readData(rw)

// 	}

// 	// Wait forever
// 	select {}
// }

// func makeHost(port int, randomness io.Reader) (host.Host, error) {
// 	// Creates a new RSA key pair for this host.
// 	prvKey, _, err := crypto.GenerateKeyPairWithReader(crypto.RSA, 2048, randomness)
// 	if err != nil {
// 		log.Println(err)
// 		return nil, err
// 	}

// 	// 0.0.0.0 will listen on any interface device.
// 	sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port))

// 	// libp2p.New constructs a new libp2p Host.
// 	// Other options can be added here.
// 	return libp2p.New(
// 		libp2p.ListenAddrs(sourceMultiAddr),
// 		libp2p.Identity(prvKey),
// 	)
// }

// func startPeer(ctx context.Context, h host.Host, streamHandler network.StreamHandler) {
// 	// Set a function as stream handler.
// 	// This function is called when a peer connects, and starts a stream with this protocol.
// 	// Only applies on the receiving side.
// 	h.SetStreamHandler("/chat/1.0.0", streamHandler)

// 	// Let's get the actual TCP port from our listen multiaddr, in case we're using 0 (default; random available port).
// 	var port string
// 	for _, la := range h.Network().ListenAddresses() {
// 		if p, err := la.ValueForProtocol(multiaddr.P_TCP); err == nil {
// 			port = p
// 			break
// 		}
// 	}

// 	if port == "" {
// 		log.Println("was not able to find actual local port")
// 		return
// 	}

// 	log.Printf("Run './chat -d /ip4/127.0.0.1/tcp/%v/p2p/%s' on another console.\n", port, h.ID().Pretty())
// 	log.Println("You can replace 127.0.0.1 with public IP as well.")
// 	log.Println("Waiting for incoming connection")
// 	log.Println()
// }

func startPeerAndConnect(h host.Host, idpeer peer.ID, hash string) (*bufio.ReadWriter, error) {
	// log.Println("This node's multiaddresses:")
	// for _, la := range h.Addrs() {
	// 	log.Printf(" - %v\n", la)
	// }
	//newmul, err := ma.NewMultiaddr("/ip4/164.90.237.203/tcp/9001")
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// }
	//fmt.Println(idpeer)
	log.Println()

	s, err := h.NewStream(context.Background(), idpeer, "/cirrus/1.0.0")
	if err != nil {
		//log.Println(err)
		return nil, err
	}
	log.Println("Established connection to destination")

	// Create a buffered stream so that read and writes are non blocking.
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))
	hs := strings.ReplaceAll(hash, "\n", "")
	go writeData(rw, hs)
	return rw, nil

	// for _, peer := range multis {
	// 	h.Connect(ctx, peer)
	// }

	// // Turn the destination into a multiaddr.
	// maddr, err := multiaddr.NewMultiaddr(multis[0])
	// if err != nil {
	// 	log.Println(err)
	// 	return nil, err
	// }

	// Extract the peer ID from the multiaddr.
	// for _, peerIDS := range multis {
	// 	fmt.Println(peerIDS)
	// 	info, err := peer.AddrInfoFromP2pAddr(newmul)
	// 	if err != nil {
	// 		fmt.Println("Error:", err)
	// 		fmt.Println(peerIDS)
	// 	}
	// 	// Add the destination's peer multiaddress in the peerstore.
	// 	// This will be used during connection and stream creation by libp2p.
	// 	h.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)

	// 	// Start a stream with the destination.
	// 	// Multiaddress of the destination peer is fetched from the peerstore using 'peerId'.
	// 	s, err := h.NewStream(context.Background(), idpeer, "/chat/1.0.0")
	// 	if err != nil {
	// 		log.Println(err)
	// 		return nil, err
	// 	}
	// 	log.Println("Established connection to destination")

	// 	// Create a buffered stream so that read and writes are non blocking.
	// 	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))
	// 	go writeData(rw, hash)
	// 	return rw, nil
	// }

	return nil, nil
}
