package main

import (
	"encoding/base64"
)

func StringToBase64(input string) string {
	// Convert the string to bytes
	data := []byte(input)

	// Encode the bytes to Base64
	base64String := base64.StdEncoding.EncodeToString(data)

	return base64String
}

// func main() {
// 	input := "Hello, World!"

// 	base64String := StringToBase64(input)

// 	fmt.Println("Original String:", input)
// 	fmt.Println("Base64 Encoding:", base64String)
// }
