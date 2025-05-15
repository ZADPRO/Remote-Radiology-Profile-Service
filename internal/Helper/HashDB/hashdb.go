package hashdb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

// Encrypt encrypts a plain text string using AES-GCM and returns a base64-encoded ciphertext.
func Encrypt(plainText string) string {
	keyBytes := []byte(os.Getenv("ENCRYPT_DB"))

	// Validate key size: AES supports only 16, 24, or 32 byte keys.
	if len(keyBytes) != 16 && len(keyBytes) != 24 && len(keyBytes) != 32 {
		fmt.Printf("invalid key size: %d bytes\n", len(keyBytes))
		return plainText
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		fmt.Printf("Something went wrong: %s\n", err)
		return plainText
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("Something went wrong: %s\n", err)
		return plainText
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Printf("Something went wrong: %s\n", err)
		return plainText
	}

	cipherText := aesGCM.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText)
}

// Decrypt decrypts a base64-encoded ciphertext string using AES-GCM and returns the original plain text.
func Decrypt(encText string) string {

	dbkey := os.Getenv("ENCRYPT_DB")
	keyBytes := []byte(dbkey)

	// Validate key size
	if len(keyBytes) != 16 && len(keyBytes) != 24 && len(keyBytes) != 32 {
		fmt.Printf("invalid key size: %d bytes\n", len(keyBytes))
		return encText
	}

	cipherData, err := base64.StdEncoding.DecodeString(encText)
	if err != nil {
		fmt.Printf("Something went wrong: %s\n", err)
		return encText
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		fmt.Printf("Something went wrong: %s\n", err)
		return encText
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("Something went wrong: %s\n", err)
		return encText
	}

	nonceSize := aesGCM.NonceSize()
	if len(cipherData) < nonceSize {
		fmt.Printf("Something went wrong: %s\n", err)
		return encText
	}

	nonce, cipherText := cipherData[:nonceSize], cipherData[nonceSize:]
	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		fmt.Printf("Something went wrong: %s\n", err)
		return encText
	}

	return string(plainText)
}
