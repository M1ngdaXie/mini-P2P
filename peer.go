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
	peer := flag.String("peer", "", "peer地址(可选,空则只靠广播发现)")
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
	publicKey := privatekey.PublicKey().Bytes()
	go BroadcastAndListen(conn, publicKey, privatekey, store, *port)
	if *peer != "" {
		peerAddr, err := net.ResolveUDPAddr("udp", *peer)
		if err != nil {
			fmt.Println("解析 peer 地址失败:", err)
			return
		}
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		go func() {
			for range ticker.C {
				// 跳过指向自己的直连目标
				if peerAddr.Port == *port {
					continue
				}
				_, ok := store.Get(peerAddr.String())
				if !ok {
					log.Printf("Dont have peer key %s tickering \n", peerAddr.String())
					err := sendPublicKey(conn, peerAddr, publicKey)
					if err != nil {
						log.Printf("Error Ticker sending PublicKey: %s\n", err)
						return
					}
				}
			}
		}()
	}
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
		addr = normalizeAddr(addr)
		log.Printf("Read %d bytes from UDP: %s\n", buf[:n], addr.String())
		switch buf[0] {
		//handshake
		case 0x00:
			err := handleHandShake(addr, conn, store, publicKey, privatekey, buf, n)
			if err != nil {
				log.Printf("Error handling handshake: %s\n", err)
				continue
			}
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

// normalizeAddr 把本机自己的局域网 IP(如 10.3.150.79)归一化成 127.0.0.1,
// 保证同一个 peer 无论通过广播还是 -peer 直连发现,都用同一个 key。
// 其他机器的 IP(如 192.168.x.x)原样保留,多机场景不受影响。
func normalizeAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr.IP.IsLoopback() || !isLocalIP(addr.IP) {
		return addr
	}
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: addr.Port}
}

// isLocalIP 判断 IP 是否属于本机某个网卡
func isLocalIP(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if ok && ipnet.IP.Equal(ip) {
			return true
		}
	}
	return false
}

func handleHandShake(peerAddr *net.UDPAddr, conn *net.UDPConn, store *peerStore,
	publicKey []byte,
	privateKey *ecdh.PrivateKey, buf []byte, n int) error {
	peerAddr = normalizeAddr(peerAddr)
	_, ok := store.Get(peerAddr.String())
	log.Printf("Sending GetResp to map \n")
	if ok {
		log.Printf("Already got the secret from %s skip \n", peerAddr.String())
		return nil
	}
	peerpk, _ := ecdh.X25519().NewPublicKey(buf[1:n])
	sharedSecret, _ := privateKey.ECDH(peerpk)
	log.Printf("generated Secret: %x\n", sharedSecret)
	hkdfKey := deriveKey(sharedSecret)
	store.Set(hkdfKey, peerAddr.String())
	err := sendPublicKey(conn, peerAddr, publicKey)
	if err != nil {
		log.Printf("Error sending public key: %s\n", err)
		return err
	}
	fmt.Printf("PK sent to %s\n", peerAddr.String())
	return nil
}
func sendPublicKey(conn *net.UDPConn, peerAddr *net.UDPAddr, publicKey []byte) error {
	var msg []byte
	msg = append([]byte{0x00}, publicKey...)
	_, err := conn.WriteToUDP(msg, peerAddr)
	if err != nil {
		log.Printf("Error writing to UDP: %s\n", err)
		return err
	}
	return nil
}
func BroadcastAndListen(conn *net.UDPConn, publicKey []byte, privateKey *ecdh.PrivateKey,
	store *peerStore, myPort int) {
	bconn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 9999})
	if err != nil {
		log.Printf("9999 被占用,降级为仅发送\n")
		sendPublicKey(conn, &net.UDPAddr{IP: net.IPv4bcast, Port: 9999}, publicKey)
		return
	}
	log.Printf("Sliently Listening on port 9999\n")
	defer bconn.Close()
	//broadcast first once
	err = sendPublicKey(conn, &net.UDPAddr{IP: net.IPv4bcast, Port: 9999}, publicKey)

	if err != nil {
		log.Printf("Error Broadcasting public key: %s\n", err)
		return
	}
	log.Printf("Public key done Broadcasting on port 9999\n")
	//then listen others
	for {
		buf := make([]byte, 4096)
		n, addr, err := bconn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Error reading from UDP: %s\n", err)
			continue
		}
		log.Printf("Received %d bytes from Broadcast by address : %s, "+
			"establishing handshake... \n", n, addr.String())
		if addr.Port == myPort {
			log.Printf("Ignoring self broadcast from %s\n", addr.String())
			continue
		}
		handleHandShake(addr, conn, store, publicKey, privateKey, buf, n)
	}

}
