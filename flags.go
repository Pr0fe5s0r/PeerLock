package main

import (
	// "crypto/rand"
	// "crypto/rsa"
	// "crypto/x509"
	// "encoding/pem"
	"flag"
	"fmt"
	"os"

	// "fmt"
	"io/ioutil"
	"log"

	// "os"

	"github.com/libp2p/go-libp2p-core/crypto"
)

type config struct {
	RendezvousString string
	ProtocolID       string
	listenHost       string
	listenPort       int
}

func parseFlags() *config {
	c := &config{}

	flag.StringVar(&c.RendezvousString, "rendezvous", "meetme", "Unique string to identify group of nodes. Share this with your friends to let them connect with you")
	flag.StringVar(&c.listenHost, "host", "0.0.0.0", "The bootstrap node host listen address\n")
	flag.StringVar(&c.ProtocolID, "pid", "/chat/1.1.0", "Sets a protocol id for stream headers")
	flag.IntVar(&c.listenPort, "port", 6001, "node listen port")

	flag.Parse()
	return c
}

func generateRSAKey() {
	privateKey, _, err := crypto.GenerateKeyPair(crypto.RSA, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %s", err)
	}

	privateKeyBytes, err := crypto.MarshalPrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Failed to marshal private key: %s", err)
	}

	err = ioutil.WriteFile("private.pem", privateKeyBytes, 0644)
	if err != nil {
		log.Fatalf("Failed to write private key to disk: %s", err)
	}
	fmt.Println("Created Private Key in private.pem")
	if _, err := os.Stat("data.json"); err == nil {
		fmt.Println("File already exists. Delete data.json manually if needed")
	} else if os.IsNotExist(err) {
		fmt.Println("Created a data.json file.")
		err = ioutil.WriteFile("data.json", []byte("[]"), 0644)
		if err != nil {
			log.Fatalf("Failed to write private key to disk: %s", err)
		}
	} else {
		// some other error occurred
		// handle the error
	}
	os.Exit(0)
}

func getRSAPrivKey() crypto.PrivKey {
	privateKeyBytes, err := ioutil.ReadFile("private.pem")
	if err != nil {
		log.Fatalf("Failed to read private key from disk: %s", err)
	}

	privateKey, err := crypto.UnmarshalPrivateKey(privateKeyBytes)
	if err != nil {
		log.Fatalf("Failed to unmarshal private key: %s", err)
	}

	return privateKey
}
