package main

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

var nonce = [24]byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
	0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
}

func SealSecretMessage(message []byte, publicKeyBHex string, privateKeyAHex string, signValue string, CID string, Contract string, Nonce string, VaultID string, permission bool) (SendData, error) {
	// Decode User B's public key from hex string
	publicKeyBBytes, err := hex.DecodeString(publicKeyBHex)
	if err != nil {
		fmt.Errorf("failed to decode User B's public key: %v", err)
	}

	var publicKeyBKey [32]byte
	copy(publicKeyBKey[:], publicKeyBBytes)

	// Decode User A's private key from hex string
	privateKeyABytes, err := hex.DecodeString(privateKeyAHex)
	if err != nil {
		fmt.Errorf("failed to decode User A's private key: %v", err)
	}

	var privateKeyAKey [32]byte
	copy(privateKeyAKey[:], privateKeyABytes)

	// Seal the secret message
	sealedMessage := box.Seal(nil, message, &nonce, &publicKeyBKey, &privateKeyAKey)

	encrypted := hex.EncodeToString(sealedMessage)

	m := SendData{
		SignedValue: signValue,
		CID:         CID,
		Contract:    Contract,
		Key:         encrypted,
		Nonce:       Nonce,
		VaultID:     VaultID,
		Rec:         "0x" + publicKeyBHex,
		Permission:  permission,
	}

	return m, nil
}

// func SealSecretMessage(message []byte, publicKeyBHex string, privateKeyAHex string) (string, error) {
// 	// Decode User B's public key from hex string
// 	publicKeyBBytes, err := hex.DecodeString(publicKeyBHex)
// 	if err != nil {
// 		fmt.Errorf("failed to decode User B's public key: %v", err)
// 	}

// 	var publicKeyBKey [32]byte
// 	copy(publicKeyBKey[:], publicKeyBBytes)

// 	// Decode User A's private key from hex string
// 	privateKeyABytes, err := hex.DecodeString(privateKeyAHex)
// 	if err != nil {
// 		fmt.Errorf("failed to decode User A's private key: %v", err)
// 	}

// 	var privateKeyAKey [32]byte
// 	copy(privateKeyAKey[:], privateKeyABytes)

// 	// Seal the secret message
// 	sealedMessage := box.Seal(nil, message, &nonce, &publicKeyBKey, &privateKeyAKey)

// 	encrypted := hex.EncodeToString(sealedMessage)

// 	return encrypted, nil
// }

func OpenSealedMessage(sealedDataHex string, publicKeyBHex string, privateKeyAHex string) ([]byte, error) {
	// Decode the sealed data from hex string
	sealedData, err := hex.DecodeString(sealedDataHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode sealed data: %v", err)
	}

	// Decode User B's public key from hex string
	publicKeyBBytes, err := hex.DecodeString(publicKeyBHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode User B's public key: %v", err)
	}

	var publicKeyBKey [32]byte
	copy(publicKeyBKey[:], publicKeyBBytes)

	// Decode User A's private key from hex string
	privateKeyABytes, err := hex.DecodeString(privateKeyAHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode User A's private key: %v", err)
	}

	var privateKeyAKey [32]byte
	copy(privateKeyAKey[:], privateKeyABytes)

	// Check if the sealed message can be opened
	decryptedMessage, ok := box.Open(nil, sealedData, &nonce, &publicKeyBKey, &privateKeyAKey)
	if !ok {
		return nil, fmt.Errorf("failed to open sealed message")
	}

	return decryptedMessage, nil
}

// func main() {
// 	message := []byte("acbdefgh")
// 	publicKeyBHex := "0x9f35C13ac826AA8ff6cfbf91CA70fDD723205DFd"
// 	privateKeyAHex := "cc64cf0896f1cfa77b23a010f48328544b01639380f3182d50a1e5ebe9ce8a50"

// 	// Remove the leading "0x"
// 	publicKeyBHex = publicKeyBHex[2:]
// 	sealedMessage, err := SealSecretMessage(message, publicKeyBHex, privateKeyAHex)
// 	if err != nil {
// 		fmt.Println("Sealing error:", err)
// 		return
// 	}

// 	decryptedMessage, err := OpenSealedMessage(sealedMessage, publicKeyBHex, privateKeyAHex)
// 	if err != nil {
// 		fmt.Println("Opening error:", err)
// 		return
// 	}

// 	fmt.Println("Decrypted Message:", sealedMessage)

// 	fmt.Println("Sealed Message:", string(decryptedMessage))
// }
