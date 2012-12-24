package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/go.crypto/nacl/box"
	"code.google.com/p/go.net/proxy"
	"code.google.com/p/goprotobuf/proto"
	pond "github.com/agl/pond/protos"
	"github.com/agl/pond/transport"
)

func (c *client) send(to *Contact, message *pond.Message) error {
	var nonce [24]byte
	c.randBytes(nonce[:])

	messageBytes, err := proto.Marshal(message)
	if err != nil {
		return err
	}

	if len(messageBytes) > pond.MaxSerializedMessage {
		return errors.New("message too large")
	}

	plaintext := make([]byte, pond.MaxSerializedMessage+4)
	binary.LittleEndian.PutUint32(plaintext, uint32(len(messageBytes)))
	copy(plaintext[4:], messageBytes)
	c.randBytes(plaintext[4+len(messageBytes):])

	sealed := make([]byte, len(plaintext)+box.Overhead+len(nonce))
	copy(sealed, nonce[:])
	box.Seal(sealed[len(nonce):len(nonce)], plaintext, &nonce, &to.theirCurrentDHPublic, &to.lastDHPrivate)

	sha := sha256.New()
	sha.Write(sealed)
	digest := sha.Sum(nil)
	sha.Reset()
	groupSig, err := to.myGroupKey.Sign(c.rand, digest, sha)
	if err != nil {
		return err
	}

	request := &pond.Request{
		Deliver: &pond.Delivery{
			To:         to.theirIdentityPublic[:],
			Signature:  groupSig,
			Generation: proto.Uint32(to.generation),
			Message:    sealed,
		},
	}
	out := &queuedMessage{
		request: request,
		id:      *message.Id,
		to:      to.id,
		server:  to.theirServer,
		message: message,
		created: time.Unix(*message.Time, 0),
	}
	c.enqueue(out)
	if len(message.Body) > 0 {
		c.outboxUI.Add(*message.Id, to.name, out.created.Format(shortTimeFormat), indicatorRed)
	}
	c.outbox = append(c.outbox, out)

	return nil
}

func decryptMessage(sealed []byte, nonce *[24]byte, from *Contact) ([]byte, bool) {
	if plaintext, ok := box.Open(nil, sealed, nonce, &from.theirLastDHPublic, &from.lastDHPrivate); ok {
		return plaintext, true
	}

	if plaintext, ok := box.Open(nil, sealed, nonce, &from.theirCurrentDHPublic, &from.lastDHPrivate); ok {
		return plaintext, true
	}

	plaintext, ok := box.Open(nil, sealed, nonce, &from.theirLastDHPublic, &from.currentDHPrivate)
	if !ok {
		plaintext, ok = box.Open(nil, sealed, nonce, &from.theirCurrentDHPublic, &from.currentDHPrivate)
		if !ok {
			return nil, false
		}
	}

	// They have clearly received our current DH value. Time to
	// rotate.
	copy(from.lastDHPrivate[:], from.currentDHPrivate[:])
	if _, err := io.ReadFull(rand.Reader, from.currentDHPrivate[:]); err != nil {
		panic(err)
	}
	return plaintext, true
}

func (c *client) processFetch(m NewMessage) {
	f := m.fetched
	defer func() { m.ack <- true }()

	// TODO: support ServerAnnounce messages.

	sha := sha256.New()
	sha.Write(f.Message)
	digest := sha.Sum(nil)

	if !c.groupPriv.Verify(digest, sha, f.Signature) {
		c.log.Errorf("Received message with bad group signature!")
		return
	}
	tag, ok := c.groupPriv.Open(f.Signature)
	if !ok {
		c.log.Errorf("Failed to open group signature")
		return
	}

	var from *Contact
	for _, candidate := range c.contacts {
		if bytes.Equal(tag, candidate.groupKey.Tag()) {
			from = candidate
			break
		}
	}
	if from == nil {
		c.log.Errorf("Message from unknown contact. Dropping. Tag: %x", tag)
		return
	}

	if len(f.Message) < box.Overhead+24 {
		c.log.Errorf("Message too small to process from %s", from.name)
		return
	}

	inboxMsg := &InboxMessage{
		id:           c.randId(),
		receivedTime: time.Now(),
		from:         from.id,
		sealed:       f.Message,
	}

	if !from.isPending {
		if !c.unsealMessage(inboxMsg, from) {
			return
		}
		if len(inboxMsg.message.Body) > 0 {
			subline := time.Unix(*inboxMsg.message.Time, 0).Format(shortTimeFormat)
			c.inboxUI.Add(inboxMsg.id, from.name, subline, indicatorBlue)
		}
	} else {
		c.inboxUI.Add(inboxMsg.id, from.name, "pending", indicatorRed)
	}

	c.inbox = append(c.inbox, inboxMsg)
	c.save()
}

func (c *client) unsealMessage(inboxMsg *InboxMessage, from *Contact) bool {
	if from.isPending {
		panic("was asked to unseal message from pending contact")
	}

	sealed := inboxMsg.sealed
	var nonce [24]byte
	copy(nonce[:], sealed)
	sealed = sealed[24:]
	plaintext, ok := decryptMessage(sealed, &nonce, from)

	if !ok {
		c.log.Errorf("Failed to decrypt message from %s", from.name)
		return false
	}

	if len(plaintext) < 4 {
		c.log.Errorf("Plaintext too small to process from %s", from.name)
		return false
	}

	mLen := int(binary.LittleEndian.Uint32(plaintext[:4]))
	plaintext = plaintext[4:]
	if mLen < 0 || mLen > len(plaintext) {
		c.log.Errorf("Plaintext length incorrect from %s: %d", from.name, mLen)
		return false
	}
	plaintext = plaintext[:mLen]

	msg := new(pond.Message)
	if err := proto.Unmarshal(plaintext, msg); err != nil {
		c.log.Errorf("Failed to parse mesage from %s: %s", from, err)
		return false
	}

	if l := len(msg.MyNextDh); l != len(from.theirCurrentDHPublic) {
		c.log.Errorf("Message from %s with bad DH length %d", from, l)
		return false
	}

	// Check for duplicate message.
	for _, candidate := range c.inbox {
		if candidate.from == from.id &&
			candidate.id != inboxMsg.id &&
			candidate.message != nil &&
			*candidate.message.Id == *msg.Id {
			c.log.Printf("Dropping duplicate message from %s", from.name)
			return false
		}
	}

	if !bytes.Equal(from.theirCurrentDHPublic[:], msg.MyNextDh) {
		// We have a new DH value from them.
		copy(from.theirLastDHPublic[:], from.theirCurrentDHPublic[:])
		copy(from.theirCurrentDHPublic[:], msg.MyNextDh)
	}

	if msg.InReplyTo != nil {
		id := *msg.InReplyTo

		for _, candidate := range c.outbox {
			if candidate.id == id {
				candidate.acked = time.Now()
				c.outboxUI.SetIndicator(id, indicatorGreen)
			}
		}
	}

	from.kxsBytes = nil
	inboxMsg.message = msg
	inboxMsg.sealed = nil
	inboxMsg.read = false

	return true
}

func (c *client) processMessageSent(id uint64) {
	for _, msg := range c.outbox {
		if msg.id == id {
			msg.sent = time.Now()
			c.outboxUI.SetIndicator(id, indicatorYellow)
			c.save()
			break
		}
	}
}

func decodeBase32(s string) ([]byte, error) {
	for len(s)%8 != 0 {
		s += "="
	}
	return base32.StdEncoding.DecodeString(s)
}

func replyToError(reply *pond.Reply) error {
	if reply.Status == nil || *reply.Status == pond.Reply_OK {
		return nil
	}
	if msg, ok := pond.Reply_Status_name[int32(*reply.Status)]; ok {
		return errors.New("error from server: " + msg)
	}
	return errors.New("unknown error from server: " + strconv.Itoa(int(*reply.Status)))
}

func parseServer(server string, testing bool) (serverIdentity *[32]byte, host string, err error) {
	url, err := url.Parse(server)
	if err != nil {
		return
	}
	if url.Scheme != "pondserver" {
		err = errors.New("bad URL scheme, should be pondserver")
		return
	}
	if url.User == nil || len(url.User.Username()) == 0 {
		err = errors.New("no server ID in URL")
		return
	}
	serverIdSlice, err := decodeBase32(url.User.Username())
	if err != nil {
		return
	}
	if len(serverIdSlice) != 32 {
		err = errors.New("bad server ID length")
		return
	}

	host = url.Host
	if !testing {
		if strings.ContainsRune(host, ':') {
			err = errors.New("URL contains a port number")
			return
		}
		if !strings.HasSuffix(host, ".onion") {
			err = errors.New("host is not a .onion address")
			return
		}
		host += ":16333"
	}

	serverIdentity = new([32]byte)
	copy(serverIdentity[:], serverIdSlice)
	return
}

// torAddr is the address at which we expect to find the local Tor SOCKS proxy.
const torAddr = "127.0.0.1:9050"

func (c *client) torDialer() proxy.Dialer {
	// We generate a random username so that Tor will decouple all of our
	// connections.
	var userBytes [8]byte
	c.randBytes(userBytes[:])
	auth := proxy.Auth{
		User:     base32.StdEncoding.EncodeToString(userBytes[:]),
		Password: "password",
	}
	dialer, err := proxy.SOCKS5("tcp", torAddr, &auth, proxy.Direct)
	if err != nil {
		panic(err)
	}
	return dialer
}

func (c *client) dialServer(server string, useRandomIdentity bool) (*transport.Conn, error) {
	identity := &c.identity
	identityPublic := &c.identityPublic
	if useRandomIdentity {
		var randomIdentity [32]byte
		c.randBytes(randomIdentity[:])

		var randomIdentityPublic [32]byte
		curve25519.ScalarBaseMult(&randomIdentityPublic, &randomIdentity)

		identity = &randomIdentity
		identityPublic = &randomIdentityPublic
	}

	serverIdentity, host, err := parseServer(server, c.testing)
	if err != nil {
		return nil, err
	}
	var tor proxy.Dialer
	if c.testing {
		tor = proxy.Direct
	} else {
		tor = c.torDialer()
	}
	rawConn, err := tor.Dial("tcp", host)
	if err != nil {
		return nil, err
	}
	// Sometimes Tor holds the connection open but we never receive
	// anything so we add a 60 second deadline.
	rawConn.SetDeadline(time.Now().Add(60 * time.Second))
	conn := transport.NewClient(rawConn, identity, identityPublic, serverIdentity)
	if err := conn.Handshake(); err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *client) doCreateAccount() error {
	_, _, err := parseServer(c.server, c.testing)
	if err != nil {
		return err
	}

	if !c.testing {
		// Check that Tor is running.
		testConn, err := net.Dial("tcp", torAddr)
		if err != nil {
			return errors.New("Failed to connect to local Tor: " + err.Error())
		}
		testConn.Close()
	}

	c.ui.Actions() <- SetText{name: "status", text: "Generating keys..."}
	c.ui.Signal()

	c.randBytes(c.identity[:])
	curve25519.ScalarBaseMult(&c.identityPublic, &c.identity)

	c.ui.Actions() <- SetText{name: "status", text: "Connecting..."}
	c.ui.Signal()

	conn, err := c.dialServer(c.server, false)
	if err != nil {
		return err
	}
	defer conn.Close()

	c.ui.Actions() <- SetText{name: "status", text: "Requesting new account..."}
	c.ui.Signal()

	c.generation = uint32(c.randId())

	request := new(pond.Request)
	request.NewAccount = &pond.NewAccount{
		Generation: proto.Uint32(c.generation),
		Group:      c.groupPriv.Group.Marshal(),
	}
	if err := conn.WriteProto(request); err != nil {
		return err
	}

	reply := new(pond.Reply)
	if err := conn.ReadProto(reply); err != nil {
		return err
	}
	if err := replyToError(reply); err != nil {
		return err
	}

	c.ui.Actions() <- SetText{name: "status", text: "Done"}
	c.ui.Signal()

	return nil
}

// transactionRateSeconds is the mean of the exponential distribution that
// we'll sample in order to distribute the time between our network
// connections.
const transactionRateSeconds = 300 // five minutes

func (c *client) transact() {
	startup := true

	var ackChan chan bool
	for {
		if !startup {
			if ackChan != nil {
				ackChan <- true
				ackChan = nil
			}

			var timerChan <-chan time.Time
			if c.autoFetch {
				var seedBytes [8]byte
				c.randBytes(seedBytes[:])
				seed := int64(binary.LittleEndian.Uint64(seedBytes[:]))
				r := mrand.New(mrand.NewSource(seed))
				delay := r.ExpFloat64() * transactionRateSeconds
				if c.testing {
					delay = 5
				}
				c.log.Printf("Next network transaction in %d seconds", int(delay))
				timerChan = time.After(time.Duration(delay*1000) * time.Millisecond)
			}
			var ok bool

			select {
			case ackChan, ok = <-c.fetchNowChan:
				if !ok {
					return
				}
				break
			case <-timerChan:
				break
			}
		}
		startup = false

		var head *queuedMessage
		var req *pond.Request
		var server string

		isFetch := false
		c.queueMutex.Lock()
		if len(c.queue) == 0 {
			isFetch = true
			req = &pond.Request{Fetch: &pond.Fetch{}}
			server = c.server
			c.log.Printf("Starting fetch from home server")
		} else {
			// We move the head to the back of the queue so that we
			// don't get stuck trying to send the same message over
			// and over.
			head = c.queue[0]
			c.queue = append(c.queue[1:], head)
			req = head.request
			server = head.server
			c.log.Printf("Starting message transmission to %s", server)
		}
		c.queueMutex.Unlock()

		conn, err := c.dialServer(server, !isFetch)
		if err != nil {
			c.log.Printf("Failed to connect to %s: %s", server, err)
			continue
		}
		if err := conn.WriteProto(req); err != nil {
			c.log.Printf("Failed to send to %s: %s", server, err)
			continue
		}

		reply := new(pond.Reply)
		if err := conn.ReadProto(reply); err != nil {
			c.log.Printf("Failed to read from %s: %s", server, err)
			continue
		}

		if reply.Status == nil {
			if isFetch && reply.Fetched != nil {
				ackChan := make(chan bool)
				c.newMessageChan <- NewMessage{reply.Fetched, ackChan}
				<-ackChan
			} else if !isFetch {
				c.queueMutex.Lock()
				c.queue = c.queue[:len(c.queue)-1]
				c.queueMutex.Unlock()
				c.messageSentChan <- head.id
			}
		}

		conn.Close()

		if err := replyToError(reply); err != nil {
			c.log.Errorf("Error from server %s: %s", server, err)
			continue
		}

	}
}
