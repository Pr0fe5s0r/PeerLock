package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	ipfs "github.com/ipfs/go-ipfs-api"
	peer "github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
)

const checkProtocol = "/libp2p/check/1.0.0"
const requestConnections = "/libp2p/connections/1.0.0"
const ipfSHash = "/libp2p/ipfhash/1.0.0"
const ipfsddress = "/libp2p/ipfsaddress/1.0.0"
const requestVault = "/libp2p/reqvault/1.0.0"
const responseVault = "/libp2p/resvault/1.0.0"
const sendData = "/libp2p/senddata/1.0.0"
const retrieveData = "/libp2p/retrivedata/1.0.0"
const retriveResponse = "/libp2p/retriveresponse/1.0.0"

// TODO: Replace this handler with a function that handles message from a
// pubsub Subscribe channel.
func ReadRequestVault(ctx context.Context, s network.Stream) (bool, peer.ID) {
	// data, err := io.ReadAll(s)
	// if err != nil {
	// 	fmt.Fprintln(os.Stderr, err)
	// }
	// fmt.Println("Received:", string(data))

	data, err := io.ReadAll(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	cm := new(Request)
	err = json.Unmarshal(data, cm)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Got a Request for a Vault: ", cm.Self)

	if _, err := os.Stat("vp.json"); os.IsNotExist(err) {
		return false, cm.Self
	} else {
		return true, cm.Self
	}
}

func SendDataR(ctx context.Context, s network.Stream) (string, string, string, string, string, string, string, bool) {
	// data, err := io.ReadAll(s)
	// if err != nil {
	// 	fmt.Fprintln(os.Stderr, err)
	// }
	// fmt.Println("Received:", string(data))

	data, err := io.ReadAll(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	cm := new(SendData)
	err = json.Unmarshal(data, cm)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Got New Data", cm)
	return cm.Contract, cm.CID, cm.Nonce, cm.SignedValue, cm.VaultID, cm.Key, cm.Rec, cm.Permission
}

func GotTheKey(ctx context.Context, s network.Stream) (string, string, bool) {
	// data, err := io.ReadAll(s)
	// if err != nil {
	// 	fmt.Fprintln(os.Stderr, err)
	// }
	// fmt.Println("Received:", string(data))

	data, err := io.ReadAll(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	cm := new(KeyResponse)
	err = json.Unmarshal(data, cm)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Got New Data", cm)
	return cm.Key, cm.Owner, true
}

func RetrivalRequest(ctx context.Context, s network.Stream) (string, string, string, string, peer.ID) {
	// data, err := io.ReadAll(s)
	// if err != nil {
	// 	fmt.Fprintln(os.Stderr, err)
	// }
	// fmt.Println("Received:", string(data))

	data, err := io.ReadAll(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	cm := new(SendData)
	err = json.Unmarshal(data, cm)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Got New Retrival Data", data)

	return cm.CID, cm.Nonce, cm.SignedValue, cm.Rec, cm.Peer
}

func ResponseForVault(ctx context.Context, s network.Stream) (string, error) {
	// data, err := io.ReadAll(s)
	// if err != nil {
	// 	fmt.Fprintln(os.Stderr, err)
	// }
	// fmt.Println("Received:", string(data))

	data, err := io.ReadAll(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return "", err
	}

	fmt.Println("Got a Reponse for a Vault Request:", string(data))
	return string(data), nil
}

// func requestVaultReply(ctx context.Context, s network.Stream) {

// 	data, err := io.ReadAll(s)
// 	if err != nil {
// 		fmt.Fprintln(os.Stderr, err)
// 	}
// 	fmt.Println("Got this", string(data))
// 	fmt.Println("Viewing Hash:", string(data))
// }

func requestConnection(ctx context.Context, chost host.Host, s network.Stream) {
	data, err := io.ReadAll(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	peerAddr, err := peer.AddrInfoFromString(string(data))
	if err != nil {
		panic(err)
	}

	peers := chost.Network().Peers()

	// Iterate over the list of peers and print their addresses
	for _, peerID := range peers {
		if peerAddr.ID.Pretty() == chost.ID().Pretty() || peerID.Pretty() == peerAddr.ID.Pretty() {
			//fmt.Println("Equal hash", peerID.Pretty())
			return
		}
	}

	fmt.Println("Connecting To hash:", peerAddr.ID.Pretty())

	errs := chost.Connect(ctx, *peerAddr)
	if errs != nil {
		fmt.Println("Can't create a connection with", peerAddr.ID)
	}
}

func ipfsHashCat(s network.Stream) {
	data, err := io.ReadAll(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	newShel := ipfs.NewShell("http://localhost:5001")
	strs := strings.ReplaceAll(string(data), "\n", "")
	datas, errw := newShel.Cat(string(strs))
	if errw != nil {
		return
	}
	if datas == nil {
		return
	}
	fmt.Println("Viewing Hash:", string(data))
}

func ipfsSwarmConnect(ctx context.Context, s network.Stream) {
	data, err := io.ReadAll(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	newShel := ipfs.NewShell("http://localhost:5001")
	strs := strings.ReplaceAll(string(data), "\n", "")
	errw := newShel.SwarmConnect(ctx, string(strs))
	if errw != nil {
		return
	}
	peerst, err := newShel.SwarmPeers(ctx)
	if err != nil {
		panic(err)
	}
	parts := strings.Split(strs, "/")

	// Get the last element of the parts slice, which should be the peer ID
	peerID := parts[len(parts)-1]
	// Iterate over the list of connected peers and check if the
	// target peer ID is present
	fmt.Println("Got IPFS MUL", strs)
	for _, peer := range peerst.Peers {
		if peer.Peer == peerID {
			fmt.Printf("Peer %s is already connected\n", peerID)
			return
		}
	}
	fmt.Println("Viewing Hash:", string(data))
}

// TODO: Replace this with a send function that publishes the string messages
// on our pubsub topic.
func chatSend(msg string, s network.Stream) error {
	fmt.Println("Sending:", msg)
	w := bufio.NewWriter(s)
	n, err := w.WriteString(msg)
	if n != len(msg) {
		return fmt.Errorf("expected to write %d bytes, wrote %d", len(msg), n)
	}
	if err != nil {
		return err
	}
	if err = w.Flush(); err != nil {
		return err
	}
	s.Close()
	//data, err := io.ReadAll(s)
	// if err != nil {
	// 	return err
	// }
	// if len(data) > 0 {
	// 	fmt.Println("Message:", string(data))
	// }
	return nil
}

func ipfsend(msg string, s network.Stream) error {
	w := bufio.NewWriter(s)
	n, err := w.WriteString(msg)
	if n != len(msg) {
		return fmt.Errorf("expected to write %d bytes, wrote %d", len(msg), n)
	}
	if err != nil {
		return err
	}
	if err = w.Flush(); err != nil {
		return err
	}
	s.Close()
	data, err := io.ReadAll(s)
	if err != nil {
		return err
	}
	if len(data) > 0 {
		fmt.Println("IPFS PEER:", string(data))
	}
	return nil
}
