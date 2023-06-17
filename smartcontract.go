package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

type ContractInfo struct {
	ContractAddress string `json:"contract"`
	TransactionHash string `json:"transaction_hash"`
}

type NextID struct {
	ID       string `json:"vault_id"`
	Contract string `json:"contract"`
	Aquired  string `json:"aquired"`
}

type Signed struct {
	SignedVal string `json:"address"`
}

func SignMessage(message string, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := crypto.Keccak256Hash([]byte(message))
	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func ParseJSON(jsonStr string) (*ContractInfo, error) {

	// Clean the JSON string by removing newline and tab characters
	jsonStr = strings.ReplaceAll(jsonStr, "\n", "")
	jsonStr = strings.ReplaceAll(jsonStr, "\t", "")
	jsonStr = strings.ReplaceAll(jsonStr, "\\", "")
	jsonStr = strings.ReplaceAll(jsonStr, "'", "")

	contractInfo := &ContractInfo{}
	err := json.Unmarshal([]byte(jsonStr), contractInfo)
	if err != nil {
		return nil, err
	}
	return contractInfo, nil
}

func ParseJSONID(jsonStr string) (*NextID, error) {

	// Clean the JSON string by removing newline and tab characters
	jsonStr = strings.ReplaceAll(jsonStr, "\n", "")
	jsonStr = strings.ReplaceAll(jsonStr, "\t", "")
	jsonStr = strings.ReplaceAll(jsonStr, "\\", "")
	jsonStr = strings.ReplaceAll(jsonStr, "'", "")

	contractInfo := &NextID{}
	err := json.Unmarshal([]byte(jsonStr), contractInfo)
	if err != nil {
		return nil, err
	}
	return contractInfo, nil
}

func ParseJSONSig(jsonStr string) (*Signed, error) {

	// Clean the JSON string by removing newline and tab characters
	jsonStr = strings.ReplaceAll(jsonStr, "\n", "")
	jsonStr = strings.ReplaceAll(jsonStr, "\t", "")
	jsonStr = strings.ReplaceAll(jsonStr, "\\", "")
	jsonStr = strings.ReplaceAll(jsonStr, "'", "")

	contractInfo := &Signed{}
	err := json.Unmarshal([]byte(jsonStr), contractInfo)
	if err != nil {
		return nil, err
	}
	return contractInfo, nil
}
func DeployVaultContract() (string, string, error) {
	// Command to run the Node.js program
	cmd := exec.Command("node", "smart/deploy.js")

	// Execute the command and capture its output
	output, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
		return "", "", err
	}

	contractInfo, err := ParseJSON(string(output))
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return "", "", err
	}

	// fmt.Println("Contract Address:", contractInfo.ContractAddress)
	// fmt.Println("Transaction Hash:", contractInfo.TransactionHash)

	return contractInfo.ContractAddress, contractInfo.TransactionHash, nil
}

func GetNextVaultID() (string, string, error) {
	// Command to run the Node.js program
	cmd := exec.Command("node", "smart/getNextID.js")

	// Execute the command and capture its output
	output, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
		return "", "", err
	}

	IDInfo, err := ParseJSONID(string(output))
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return "", "", err
	}

	// fmt.Println("Contract Address:", contractInfo.ContractAddress)
	// fmt.Println("Transaction Hash:", contractInfo.TransactionHash)

	return IDInfo.ID, IDInfo.Contract, nil
}

func SignAValue(nonce string) (string, error) {
	// Command to run the Node.js program
	cmd := exec.Command("node", "smart/address.js", "s", nonce)

	// Execute the command and capture its output
	output, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
		return "", err
	}

	IDInfo, err := ParseJSONSig(string(output))
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return "", err
	}

	// fmt.Println("Contract Address:", contractInfo.ContractAddress)
	// fmt.Println("Transaction Hash:", contractInfo.TransactionHash)

	return IDInfo.SignedVal, nil
}

func GetAddressFrom(nonce string, signed string) (string, error) {
	// Command to run the Node.js program

	fmt.Println("Checking to De-Sign it", nonce, signed)
	cmd := exec.Command("node", "smart/address.js", "g", nonce, signed)

	// Execute the command and capture its output
	output, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
		return "", err
	}

	IDInfo, err := ParseJSONSig(string(output))
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return "", err
	}

	// fmt.Println("Contract Address:", contractInfo.ContractAddress)
	// fmt.Println("Transaction Hash:", contractInfo.TransactionHash)

	return IDInfo.SignedVal, nil
}

func GetCustomsNextVaultID(contract string) (string, string, error) {
	// Command to run the Node.js program
	cmd := exec.Command("node", "smart/getNextID.js", contract)

	fmt.Println(cmd.Args)
	// Execute the command and capture its output
	output, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
		return "", "", err
	}

	IDInfo, err := ParseJSONID(string(output))
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return "", "", err
	}

	fmt.Println("Contract Address:", IDInfo.ID)
	// fmt.Println("Transaction Hash:", contractInfo.TransactionHash)

	return IDInfo.ID, IDInfo.Contract, nil
}

func GetOwnerOFVault(contract string, vautID string) (string, error) {
	// Command to run the Node.js program
	cmd := exec.Command("node", "smart/checkIF.js", contract, vautID)

	// Execute the command and capture its output
	output, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
		return "", err
	}

	IDInfo, err := ParseJSONSig(string(output))
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return "", err
	}

	// fmt.Println("Contract Address:", contractInfo.ContractAddress)
	// fmt.Println("Transaction Hash:", contractInfo.TransactionHash)

	return IDInfo.SignedVal, nil
}

func AquireVault(contract string) (string, string, string, error) {

	ID, _, err := GetCustomsNextVaultID(contract)

	// Command to run the Node.js program
	cmd := exec.Command("node", "smart/acquireVault.js", contract, ID)
	// Execute the command and capture its output
	output, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
		return "", "", "", err
	}

	IDInfo, err := ParseJSONID(string(output))
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return "", "", "", err
	}

	// fmt.Println("Contract Address:", contractInfo.ContractAddress)
	// fmt.Println("Transaction Hash:", contractInfo.TransactionHash)

	return IDInfo.ID, IDInfo.Contract, IDInfo.Aquired, nil
}
