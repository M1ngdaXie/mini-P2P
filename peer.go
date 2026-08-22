package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

type SetReq struct {
	Address string
	Secret  []byte
}
type peerStore struct {
	setChan  chan SetReq
	getChan  chan GetReq
	listChan chan ListReq
}
type ListReq struct {
	Reply chan map[string][]byte
}
type GetReq struct {
	Address string
	Reply   chan GetResp
}
type GetResp struct {
	Secret []byte
	Exists bool
}

func newPeerStore(bufferSize int) *peerStore {
	store := &peerStore{
		setChan:  make(chan SetReq, bufferSize),
		getChan:  make(chan GetReq, bufferSize),
		listChan: make(chan ListReq, bufferSize),
	}
	go store.run()
	return store
}

func (p *peerStore) run() {
	peerList := make(map[string][]byte)
	for {
		select {
		case set := <-p.setChan:
			peerList[set.Address] = set.Secret
		case get := <-p.getChan:
			secret, exists := peerList[get.Address]
			get.Reply <- GetResp{Secret: secret, Exists: exists}
		case list := <-p.listChan:
			snapshot := make(map[string][]byte, len(peerList))
			for k, v := range peerList {
				snapshot[k] = v
			}
			list.Reply <- snapshot
		}
	}
}
func (p *peerStore) Get(address string) ([]byte, bool) {
	replyChan := make(chan GetResp, 1)
	p.getChan <- GetReq{address, replyChan}
	resp := <-replyChan
	return resp.Secret, resp.Exists
}

func (p *peerStore) Set(secret []byte, address string) {
	p.setChan <- SetReq{Secret: secret, Address: address}
}
func (p *peerStore) List() map[string][]byte {
	replyChan := make(chan map[string][]byte, 1)
	p.listChan <- ListReq{Reply: replyChan}
	return <-replyChan
}
func main() {
	port := flag.Int("port", 9001, "服务器监听的端口")
	peer := flag.String("peer", "127.0.0.1:9002", "peer地址")
	flag.Parse()
	store := newPeerStore(10)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: *port})
	if err != nil {
		log.Printf("Error listening on port 9001: %s\n", err)
		return
	}
	defer conn.Close()
	log.Printf("Listening on port %d\n", *port)
	privatekey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	publickey := privatekey.PublicKey().Bytes()
	peerAddr, err := net.ResolveUDPAddr("udp", *peer)
	if err != nil {
		fmt.Println("解析 peer 地址失败:", err)
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	go func() {
		for range ticker.C {
			_, ok := store.Get(peerAddr.String())
			if !ok {
				var msg []byte
				msg = append([]byte{0x00}, publickey...)
				_, err = conn.WriteToUDP(msg, peerAddr)
				if err != nil {
					log.Printf("Error writing to UDP: %s\n", err)
					return
				}
			}
		}
	}()
	go func() {
		for {
			message, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(message, "@") {
				parts := strings.SplitN(message, " ", 2)
				if len(parts) < 2 {
					log.Println("Invalid message format. Usage: @port message")
					continue
				}

				rawTarget := parts[0] // e.g. "@8080" 或 "@127.0.0.1:8080"
				text := parts[1]      // e.g. "hello"

				target := strings.TrimPrefix(rawTarget, "@")

				receiverAddr, err := net.ResolveUDPAddr("udp", target)
				if err != nil {
					log.Printf("Error resolving udp address : %s\n", err)
					continue
				}

				secret, ok := store.Get(receiverAddr.String())
				if !ok {
					log.Printf("Error getting secret for target %s\n", target)
					continue
				}

				encrypted, err := encrypt(secret, []byte(text))
				if err != nil {
					log.Printf("Error encrypting message: %s\n", err)
					continue
				}

				msg := append([]byte{0x01}, encrypted...)
				_, err = conn.WriteToUDP(msg, receiverAddr)
				if err != nil {
					log.Printf("Error writing UDP: %s\n", err)
				}

			} else if strings.HasPrefix(message, "/") {

				if strings.HasPrefix(message, "/list") {
					all := store.List()
					for k, v := range all {
						fmt.Printf("List -> Key: %s, Val: %s\n", k, v)
					}
				}
			} else {
				all := store.List()
				for addr, _ := range all {
					key, ok := store.Get(addr)
					if !ok {
						log.Printf("Error getting key for %s\n", addr)
						continue
					}
					encrypted, err := encrypt(key, []byte(message))
					if err != nil {
						log.Printf("Error encrypting message: %s\n", err)
						continue
					}
					msg := append([]byte{0x01}, encrypted...)
					udpaddr, err := net.ResolveUDPAddr("udp", addr)
					if err != nil {
						log.Printf("Error resolving udp address : %s\n", err)
						continue
					}
					_, err = conn.WriteToUDP(msg, udpaddr)
					if err != nil {
						log.Printf("Error writing UDP: %s\n", err)
					}
				}
			}
		}
	}()
	for {
		buf := make([]byte, 4096)
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Error reading from UDP: %s\n", err)
			return
		}
		log.Printf("Read %d bytes from UDP: %s\n", buf[:n], addr.String())
		switch buf[0] {
		//handshake
		case 0x00:
			_, ok := store.Get(addr.String())
			log.Printf("Sending GetResp to map \n")
			if ok {
				log.Printf("Already got the secret from %s\n ignoring", addr.String())
				continue
			}
			peerpk, _ := ecdh.X25519().NewPublicKey(buf[1:n])
			sharedSecret, _ := privatekey.ECDH(peerpk)
			log.Printf("generated Secret: %x\n", sharedSecret)
			store.Set(sharedSecret, addr.String())
			var msg []byte
			msg = append([]byte{0x00}, publickey...)
			_, err = conn.WriteToUDP(msg, addr)
			if err != nil {
				log.Printf("Error writing to UDP: %s\n", err)
			}
			fmt.Printf("PK sent to %s\n", addr.String())
		//message
		case 0x01:
			secret, ok := store.Get(addr.String())
			if !ok {
				log.Printf("No secret received from %s\n yet", addr.String())
				continue
			}
			ciphertext := buf[1:n]
			decrypted, err := decrypt(secret, ciphertext)
			if err != nil {
				log.Printf("Error decrypting ciphertext: %s\n", err)
				return
			}
			fmt.Printf("message from %s : %s\n", addr.String(), decrypted)
		}
	}
}
