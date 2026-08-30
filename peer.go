package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	mrand "math/rand"
	"net"
	"os"
	"strings"
	"time"
)

var mySessionId []byte = GetSessionId()

// 握手包的两种类型。载荷完全一样([sessionId 16][pubkey 32]),
// 区别只在类型字节携带的那 1 比特信息:发送方是否已经拿到了收信方的公钥。
const (
	typeHandshake        byte = 0x00 // 这是我的公钥;我还没有你的
	typeHandshakeConfirm byte = 0x03 // 这是我的公钥;我已经有你的了
)

// 握手包定长:1(type) + 16(sessionId) + 32(pubkey)
const handshakeLen = 49

// 巡逻的重发上限。两军问题决定了"对方一定收到了我的确认"无法被证明,
// 所以只能有界重试:发够这么多次就停,剩下的交给数据层的 ACK 去暴露。
const maxPatrol = 10

type SetReq struct {
	Address      string
	Secret       []byte
	State        status
	LastSeen     time.Time
	SessionId    []byte
	PeerHasMyKey bool
}
type IncrementReq struct {
	Address string
	Reply   chan uint64
}

type peerStore struct {
	setChan       chan SetReq
	getChan       chan GetReq
	listChan      chan ListReq
	changeChan    chan ChangeReq
	incrementChan chan IncrementReq
	PatrolChan    chan PatrolReq
}
type changewhat string

const (
	changeSessionId    changewhat = "sessionId"
	changeState        changewhat = "state"
	changePeerHasMyKey changewhat = "peerHasMyKey" // 收到对方的 0x03
	changePatrolSent   changewhat = "patrolSent"   // 我发出了一个 0x03
)

type ChangeReq struct {
	Changewhat changewhat
	Address    string
	SessionId  []byte
	State      status
}
type ListReq struct {
	Reply chan map[string][]string
}
type GetReq struct {
	Address string
	Reply   chan GetResp
}
type GetResp struct {
	Peer   Peer
	Exists bool
}
type status string

const (
	statusPending status = "handshaking"
	statusSuccess status = "established"
)

type Peer struct {
	Address   string
	Secret    []byte
	State     status
	LastSeen  time.Time
	SessionId []byte
	SendSeq   uint64

	// 握手是否双向坐实。两个都为真时巡逻才停:
	//   PeerHasMyKey — 它告诉过我"我有你的公钥"(收到过它的 0x03)
	//   SentConfirm  — 我告诉过它"我有你的公钥"(发出过 0x03)
	// 缺任何一个都说明还有一方蒙在鼓里,必须继续巡逻。
	PeerHasMyKey bool
	SentConfirm  bool
	PatrolCount  int
}

type PatrolReq struct {
	relayChan chan []string
}

func newPeerStore(bufferSize int) *peerStore {
	store := &peerStore{
		setChan:       make(chan SetReq, bufferSize),
		getChan:       make(chan GetReq, bufferSize),
		listChan:      make(chan ListReq, bufferSize),
		changeChan:    make(chan ChangeReq, bufferSize),
		incrementChan: make(chan IncrementReq, bufferSize),
		PatrolChan:    make(chan PatrolReq, bufferSize),
	}
	go store.run()
	return store
}

func (p *peerStore) run() {
	peerList := make(map[string]Peer)
	for {
		select {
		case set := <-p.setChan:
			_, ok := peerList[set.Address]
			if ok {
				log.Printf("In select, peer %s already exists", set.Address)
				continue
			}
			peerList[set.Address] = Peer{
				Address:      set.Address,
				Secret:       set.Secret,
				State:        set.State,
				LastSeen:     set.LastSeen,
				SessionId:    set.SessionId,
				SendSeq:      0,
				PeerHasMyKey: set.PeerHasMyKey,
			}
		case get := <-p.getChan:
			peer, exists := peerList[get.Address]
			get.Reply <- GetResp{Peer: peer, Exists: exists}
		case list := <-p.listChan:
			snapshot := make(map[string][]string, len(peerList))
			for k, v := range peerList {
				if v.State == statusSuccess {
					snapshot[k] = append(snapshot[k], "Established")
				} else {
					snapshot[k] = append(snapshot[k], "Handshaking")
				}
			}
			list.Reply <- snapshot
		case change := <-p.changeChan:
			peer, ok := peerList[change.Address]
			if !ok {
				log.Printf("peer %s not found", change.Address)
				continue
			}
			switch change.Changewhat {
			case changeSessionId:
				peer.SessionId = change.SessionId
			case changeState:
				peer.State = change.State
				peer.LastSeen = time.Now()
			case changePeerHasMyKey:
				peer.PeerHasMyKey = true
				peer.LastSeen = time.Now()
			case changePatrolSent:
				peer.SentConfirm = true
				peer.PatrolCount++
			}
			peerList[change.Address] = peer
		case increment := <-p.incrementChan:
			peer, ok := peerList[increment.Address]
			if !ok {
				log.Printf("peer %s not found", increment.Address)
				continue
			}
			peer.SendSeq += 1
			peerList[increment.Address] = peer
			increment.Reply <- peer.SendSeq
		case patrol := <-p.PatrolChan:
			snapshot := make([]string, 0, len(peerList))
			for _, peer := range peerList {
				// 双方都确认过了 → 握手坐实,不用再发。
				if peer.PeerHasMyKey && peer.SentConfirm {
					continue
				}
				// 重试到上限仍未坐实 → 放弃,别永远刷包。
				if peer.PatrolCount >= maxPatrol {
					continue
				}
				snapshot = append(snapshot, peer.Address)
			}
			patrol.relayChan <- snapshot
		}
	}
}
func (p *peerStore) increment(address string) uint64 {
	replyChan := make(chan uint64, 1)
	p.incrementChan <- IncrementReq{Address: address, Reply: replyChan}
	return <-replyChan
}
func (p *peerStore) Get(address string) (Peer, bool) {
	replyChan := make(chan GetResp, 1)
	p.getChan <- GetReq{address, replyChan}
	resp := <-replyChan
	return resp.Peer, resp.Exists
}

// Set 只在首次见到一个 peer 时创建条目。peerHasMyKey 必须在创建时一并写入 ——
// 如果拆成"先 Set 再 Change",两个请求走的是不同的 channel,owner 的 select
// 是伪随机挑选的,Change 可能先被处理从而找不到 peer,那 1 比特就丢了。
func (p *peerStore) Set(secret []byte, address string, LastSeen time.Time,
	SessionId []byte, peerHasMyKey bool) {
	p.setChan <- SetReq{Secret: secret, Address: address, State: statusPending,
		LastSeen: LastSeen, SessionId: SessionId, PeerHasMyKey: peerHasMyKey}
}
func (p *peerStore) List() map[string][]string {
	replyChan := make(chan map[string][]string, 1)
	p.listChan <- ListReq{Reply: replyChan}
	return <-replyChan
}
func (p *peerStore) ChangeState(address string) {
	p.changeChan <- ChangeReq{
		Changewhat: changeState,
		Address:    address,
		State:      statusSuccess,
	}
}
// SetPeerHasMyKey 记下"对方已经拿到我的公钥"(收到它的 0x03 时调用)。
func (p *peerStore) SetPeerHasMyKey(address string) {
	p.changeChan <- ChangeReq{Changewhat: changePeerHasMyKey, Address: address}
}

// MarkPatrolSent 记下"我已经告诉过它我有它的公钥",并累加重试计数。
func (p *peerStore) MarkPatrolSent(address string) {
	p.changeChan <- ChangeReq{Changewhat: changePatrolSent, Address: address}
}

func (p *peerStore) PatrolPeers() []string {
	replyChan := make(chan []string, 1)
	p.PatrolChan <- PatrolReq{relayChan: replyChan}
	return <-replyChan
}
func main() {
	port := flag.Int("port", 9001, "服务器监听的端口")
	peer := flag.String("peer", "", "peer地址(可选,空则只靠广播发现)")
	loss := flag.Float64("loss", 0.0, "丢包率测试")
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
	go StartPatrol(store, 1.0, conn, publicKey)
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
				log.Printf("Sending keys to peer %s every 5 second \n", peerAddr.String())
				if !ok {
					log.Printf("Dont have peer key %s tickering \n", peerAddr.String())
					err := sendPublicKey(conn, peerAddr, publicKey, typeHandshake)
					if err != nil {
						log.Printf("Error Ticker sending PublicKey: %s\n", err)
						return
					}
				}
			}
		}()
	}
	go func() {
		stdinReader := bufio.NewReader(os.Stdin)
		for {
			message, err := stdinReader.ReadString('\n')
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

				peer, ok := store.Get(receiverAddr.String())
				if !ok {
					log.Printf("Error getting secret for target %s\n", target)
					continue
				}

				encrypted, err := encrypt(peer.Secret, []byte(text))
				if err != nil {
					log.Printf("Error encrypting message: %s\n", err)
					continue
				}
				nextSeq := store.increment(receiverAddr.String())
				msg := append(append([]byte{0x01}, Uint64ToBytes(nextSeq)...), encrypted...)
				err = Write(conn, receiverAddr, msg, *loss)
				if err != nil {
					log.Printf("Error writing UDP: %s\n", err)
				}

			} else if strings.HasPrefix(message, "/") {

				if strings.HasPrefix(message, "/list") {
					all := store.List()
					for k, v := range all {
						fmt.Printf("Peer %s -> %s\n", k, v[0])
					}
				}
			} else {
				var all map[string][]string
				all = store.List()
				for k, _ := range all {
					peer, ok := store.Get(k)
					if !ok {
						log.Printf("Error getting key for %s\n", k)
						continue
					}
					encrypted, err := encrypt(peer.Secret, []byte(message))
					if err != nil {
						log.Printf("Error encrypting message: %s\n", err)
						continue
					}
					nextSeq := store.increment(k)
					msg := append(append([]byte{0x01}, Uint64ToBytes(nextSeq)...), encrypted...)
					udpaddr, err := net.ResolveUDPAddr("udp", k)
					if err != nil {
						log.Printf("Error resolving udp address : %s\n", err)
						continue
					}
					err = Write(conn, udpaddr, msg, *loss)
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
		if n < 1 {
			continue
		}
		if err != nil {
			log.Printf("Error reading from UDP: %s\n", err)
			return
		}
		addr = normalizeAddr(addr)
		log.Printf("Read %d bytes from UDP: %s\n", buf[:n], addr.String())
		switch buf[0] {
		//handshake (0x00 = 我还没有你的公钥, 0x03 = 我已经有你的了)
		case typeHandshake, typeHandshakeConfirm:
			err := handleHandShake(addr, conn, store, publicKey, privatekey, buf, n)
			if err != nil {
				log.Printf("Error handling handshake: %s\n", err)
				continue
			}
		//message
		case 0x01:
			err := handleMessage(conn, store, addr.String(), buf, n)
			if err != nil {
				log.Printf("Error handling message: %s\n", err)
				continue
			}
		case 0x02:
			if len(buf) < 9 {
				log.Printf("Wrong schema for ACK : %s\n", err)
				continue
			}
			seq := buf[1:9]
			fmt.Printf("Message #%d Ack received from peer %s \n", seq, addr.String())
			store.ChangeState(addr.String())
			log.Printf("Set state Established for %s\n", addr.String())
		}
	}
}
func Write(conn *net.UDPConn, addr *net.UDPAddr, msg []byte, loss float64) error {
	if mrand.Float64() < loss {
		log.Printf("Drop message for Peer:%s with loss rate of %f, seqNum: #%d\n",
			addr.String(), loss, binary.BigEndian.Uint64(msg[1:9]))
		return nil
	}
	_, err := conn.WriteToUDP(msg, addr)
	if err != nil {
		return err
	}
	return nil
}
func handleMessage(conn *net.UDPConn, store *peerStore, addr string, buf []byte, n int) error {
	peer, ok := store.Get(addr)
	if !ok {
		log.Printf("No secret received from %s\n yet", addr)
		return nil
	}
	seq := buf[1:9]
	ciphertext := buf[9:n]
	decrypted, err := decrypt(peer.Secret, ciphertext)
	if err != nil {
		log.Printf("Error decrypting ciphertext: %s\n", err)
		return err
	}
	fmt.Printf("message from %s:%s, seqNumber:#%d\n", addr, decrypted, binary.BigEndian.Uint64(seq))
	var msg []byte
	msg = append([]byte{0x02}, seq...)
	udpaddr, err := net.ResolveUDPAddr("udp", addr)
	_, err = conn.WriteToUDP(msg, udpaddr)
	if err != nil {
		log.Printf("Error writing ACK: %s\n", err)
		return err
	}
	store.ChangeState(addr)
	return nil
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
	if n != handshakeLen {
		log.Printf("Bad handshake length from %s: got %d, want %d\n",
			peerAddr.String(), n, handshakeLen)
		return nil
	}
	peerAddr = normalizeAddr(peerAddr)

	// 类型字节携带的那 1 比特:对方说它已经有我的公钥了。
	confirmed := buf[0] == typeHandshakeConfirm

	_, ok := store.Get(peerAddr.String())
	if ok {
		// 已经有它的密钥了,不必重新派生(重新派生会连带重置 State 和 SendSeq)。
		// 但那 1 比特仍要收下 —— 它正是巡逻停止的依据。
		if confirmed {
			store.SetPeerHasMyKey(peerAddr.String())
		}
		return nil
	}

	sid := buf[1:17]
	//if !bytes.Equal(sid, peer.SessionId){
	//	// #TODO handles close connection mechanism
	//}
	peerpk, err := ecdh.X25519().NewPublicKey(buf[17:n])
	if err != nil {
		log.Printf("Error generating public key: %s\n", err)
		return err
	}
	sharedSecret, err := privateKey.ECDH(peerpk)
	if err != nil {
		log.Printf("Error generating shared secret: %s\n", err)
		return err
	}
	log.Printf("generated Secret: %x\n", sharedSecret)
	hkdfKey := deriveKey(sharedSecret)
	// 不在这里回包 —— 回包是巡逻队的活。收到包就回包会让两边互为镜子。
	store.Set(hkdfKey, peerAddr.String(), time.Now(), sid, confirmed)
	return nil
}
// sendPublicKey 发一个握手包。msgType 决定它是 0x00(我还没有你的公钥)
// 还是 0x03(我已经有你的了) —— 载荷两者完全相同。
func sendPublicKey(conn *net.UDPConn, peerAddr *net.UDPAddr, publicKey []byte,
	msgType byte) error {
	var msg []byte
	msg = append(append([]byte{msgType}, mySessionId...), publicKey...)
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
		sendPublicKey(conn, &net.UDPAddr{IP: net.IPv4bcast, Port: 9999}, publicKey, typeHandshake)
		return
	}
	log.Printf("Sliently Listening on port 9999\n")
	defer bconn.Close()
	//broadcast first once —— 广播时还不知道收信方是谁,所以只能是 0x00
	err = sendPublicKey(conn, &net.UDPAddr{IP: net.IPv4bcast, Port: 9999}, publicKey, typeHandshake)

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
func GetSessionId() []byte {
	id := make([]byte, 16)
	_, err := rand.Read(id)
	if err != nil {
		log.Printf("Error generating session id: %s\n", err)
		return nil
	}
	return id
}
func Uint64ToBytes(n uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, n)
	return buf
}
func StartPatrol(store *peerStore, t float64, conn *net.UDPConn, publicKey []byte) {
	duration := time.Duration(t * float64(time.Second))
	ticker := time.NewTicker(duration)
	defer ticker.Stop()

	log.Printf("Patrol started, interval: %.2fs", t)

	for range ticker.C {
		// 列表为空是稳态,不是事件 —— 不打日志,让"安静"成为正常输出。
		for i, addrStr := range store.PatrolPeers() {
			addrStr = strings.TrimSpace(addrStr)
			peeraddr, err := net.ResolveUDPAddr("udp", addrStr)
			if err != nil {
				log.Printf("❌ Patrol: 解析地址失败 [%d] '%s': %v", i, addrStr, err)
				continue
			}
			// 能进巡逻列表就说明它在 map 里,而进 map 的前提是密钥已派生成功,
			// 所以这里发的一定是 0x03:"我已经有你的公钥了"。
			if err := sendPublicKey(conn, peeraddr, publicKey, typeHandshakeConfirm); err != nil {
				continue
			}
			store.MarkPatrolSent(addrStr)
			log.Printf("🔑 Patrol: 已确认公钥 → %s", addrStr)
		}
	}
}
