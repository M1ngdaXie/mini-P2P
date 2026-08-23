package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"log"
)

func deriveKey(rawSecret []byte) []byte {
	var protocolSalt = []byte("mini-p2p-v1")
	aesKey, err := hkdf.Key(sha256.New, rawSecret, protocolSalt, "Mingda is damowang", 32)
	if err != nil {
		log.Printf("hkdf derive key error: %v", err)
		return nil
	}
	return aesKey
}

func encrypt(shared, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, 12)
	rand.Read(nonce)
	block, err := aes.NewCipher(shared)
	if err != nil {
		return nil, err
	}
	gcm, _ := cipher.NewGCM(block)
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(key, data []byte) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	return gcm.Open(nil, data[:12], data[12:], nil)
}
