package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

//var sharedKey, _ = hex.DecodeString("808ae593438bca380f55a2314fe39c19808ae593438bca380f55a2314fe39c19")

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
