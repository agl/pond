package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/go.crypto/nacl/box"
	"code.google.com/p/go.net/proxy"
	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/ed25519"
	"github.com/agl/pond/bbssig"
	pond "github.com/agl/pond/protos"
	"github.com/agl/pond/transport"
)

const (
	// nonceLen is the length of a NaCl nonce.
	nonceLen = 24
	// ephemeralBlockLen is the length of the signcrypted, ephemeral key
	// used when Contact.supportedVersion >= 1.
	ephemeralBlockLen = nonceLen + 32 + box.Overhead
)

func (c *client) sendAck(msg *InboxMessage) {
	// First, see if we can merge this ack with a message to the same
	// contact that is pending transmission.
	c.queueMutex.Lock()
	for _, queuedMsg := range c.queue {
		if queuedMsg.sending {
			continue
		}
		if msg.from == queuedMsg.to && !queuedMsg.revocation {
			proto := queuedMsg.message
			proto.AlsoAck = append(proto.AlsoAck, msg.message.GetId())
			if !tooLarge(queuedMsg) {
				c.queueMutex.Unlock()
				c.log.Printf("ACK merged with queued message.")
				// All done.
				return
			}

			proto.AlsoAck = proto.AlsoAck[:len(proto.AlsoAck)-1]
			if len(proto.AlsoAck) == 0 {
				proto.AlsoAck = nil
			}
		}
	}
	c.queueMutex.Unlock()

	to := c.contacts[msg.from]
	var myNextDH []byte
	if to.ratchet == nil {
		var nextDHPub [32]byte
		curve25519.ScalarBaseMult(&nextDHPub, &to.currentDHPrivate)
		myNextDH = nextDHPub[:]
	}

	id := c.randId()
	err := c.send(to, &pond.Message{
		Id:               proto.Uint64(id),
		Time:             proto.Int64(time.Now().Unix()),
		Body:             make([]byte, 0),
		BodyEncoding:     pond.Message_RAW.Enum(),
		MyNextDh:         myNextDH,
		InReplyTo:        msg.message.Id,
		SupportedVersion: proto.Int32(protoVersion),
	})
	if err != nil {
		c.log.Errorf("Error sending message: %s", err)
	}
}

// send encrypts |message| and enqueues it for transmission.
func (c *client) send(to *Contact, message *pond.Message) error {
	messageBytes, err := proto.Marshal(message)
	if err != nil {
		return err
	}

	if len(messageBytes) > pond.MaxSerializedMessage {
		return errors.New("message too large")
	}

	out := &queuedMessage{
		id:      *message.Id,
		to:      to.id,
		server:  to.theirServer,
		message: message,
		created: time.Unix(*message.Time, 0),
	}
	c.enqueue(out)
	c.outbox = append(c.outbox, out)

	return nil
}

func (c *client) sendDraft(draft *Draft) (uint64, time.Time, error) {
	to := c.contacts[draft.to]

	// Zero length bodies are ACKs.
	if len(draft.body) == 0 {
		draft.body = " "
	}

	id := c.randId()
	created := c.Now()
	message := &pond.Message{
		Id:               proto.Uint64(id),
		Time:             proto.Int64(created.Unix()),
		Body:             []byte(draft.body),
		BodyEncoding:     pond.Message_RAW.Enum(),
		Files:            draft.attachments,
		DetachedFiles:    draft.detachments,
		SupportedVersion: proto.Int32(protoVersion),
	}

	if r := draft.inReplyTo; r != 0 {
		message.InReplyTo = proto.Uint64(r)
	}

	if to.ratchet == nil {
		var nextDHPub [32]byte
		curve25519.ScalarBaseMult(&nextDHPub, &to.currentDHPrivate)
		message.MyNextDh = nextDHPub[:]
	}

	err := c.send(to, message)
	return id, created, err
}

// tooLarge returns true if the given message is too large to serialise.
func tooLarge(msg *queuedMessage) bool {
	messageBytes, err := proto.Marshal(msg.message)
	if err != nil {
		return true
	}

	return len(messageBytes) > pond.MaxSerializedMessage
}

// processSigningRequest is run on the main goroutine in response to a request
// from the network thread to apply a group signature to a message that is just
// about to be sent to the destination server.
func (c *client) processSigningRequest(sigReq signingRequest) {
	defer close(sigReq.resultChan)
	to := c.contacts[sigReq.msg.to]

	messageBytes, err := proto.Marshal(sigReq.msg.message)
	if err != nil {
		c.log.Printf("Failed to sign outgoing message: %s", err)
		return
	}

	if len(messageBytes) > pond.MaxSerializedMessage {
		c.log.Printf("Failed to sign outgoing message because it's too large")
		return
	}

	// All messages are padded to the maximum length.
	plaintext := make([]byte, pond.MaxSerializedMessage+4)
	binary.LittleEndian.PutUint32(plaintext, uint32(len(messageBytes)))
	copy(plaintext[4:], messageBytes)
	c.randBytes(plaintext[4+len(messageBytes):])

	var sealed []byte
	if to.ratchet != nil {
		sealed = to.ratchet.Encrypt(sealed, plaintext)
	} else {
		// The message is encrypted to an ephemeral key so that the sending
		// client can choose not to store it and then cannot decrypt it once
		// sent.

		//            +---------------------+            +---...
		// outerNonce | ephemeral DH public | innerNonce | message
		// (24 bytes) |                     | (24 bytes) |
		//            +---------------------+            +---....

		sealedLen := ephemeralBlockLen + nonceLen + len(plaintext) + box.Overhead
		sealed = make([]byte, sealedLen)
		var outerNonce [24]byte
		c.randBytes(outerNonce[:])
		copy(sealed, outerNonce[:])
		x := sealed[nonceLen:]

		public, private, err := box.GenerateKey(c.rand)
		if err != nil {
			c.log.Printf("Failed to generate key for outgoing message: %s", err)
			return
		}
		box.Seal(x[:0], public[:], &outerNonce, &to.theirCurrentDHPublic, &to.lastDHPrivate)
		x = x[len(public)+box.Overhead:]

		var innerNonce [24]byte
		c.randBytes(innerNonce[:])
		copy(x, innerNonce[:])
		x = x[nonceLen:]
		box.Seal(x[:0], plaintext, &innerNonce, &to.theirCurrentDHPublic, private)
	}

	sha := sha256.New()
	sha.Write(sealed)
	digest := sha.Sum(nil)
	sha.Reset()
	groupSig, err := to.myGroupKey.Sign(c.rand, digest, sha)
	if err != nil {
		c.log.Printf("Failed to sign outgoing message: %s", err)
		return
	}

	request := &pond.Request{
		Deliver: &pond.Delivery{
			To:             to.theirIdentityPublic[:],
			GroupSignature: groupSig,
			Generation:     proto.Uint32(to.generation),
			Message:        sealed,
		},
	}

	sigReq.resultChan <- request
}

// revocationSignaturePrefix is prepended to a SignedRevocation_Revocation
// message before signing in order to give context to the signature.
var revocationSignaturePrefix = []byte("revocation\x00")

func (c *client) revoke(to *Contact) *queuedMessage {
	to.revoked = true
	revocation := c.groupPriv.GenerateRevocation(to.groupKey)
	now := time.Now()

	groupCopy, _ := new(bbssig.Group).Unmarshal(c.groupPriv.Group.Marshal())
	groupPrivCopy, _ := new(bbssig.PrivateKey).Unmarshal(groupCopy, c.groupPriv.Marshal())
	c.prevGroupPrivs = append(c.prevGroupPrivs, previousGroupPrivateKey{
		priv:    groupPrivCopy,
		expired: now,
	})

	for _, contact := range c.contacts {
		if contact == to {
			continue
		}
		contact.previousTags = append(contact.previousTags, previousTag{
			tag:     contact.groupKey.Tag(),
			expired: now,
		})
		contact.groupKey.Update(revocation)
	}

	rev := &pond.SignedRevocation_Revocation{
		Revocation: revocation.Marshal(),
		Generation: proto.Uint32(c.generation),
	}

	c.groupPriv.Group.Update(revocation)
	c.generation++

	revBytes, err := proto.Marshal(rev)
	if err != nil {
		panic(err)
	}

	var signed []byte
	signed = append(signed, revocationSignaturePrefix...)
	signed = append(signed, revBytes...)

	sig := ed25519.Sign(&c.priv, signed)

	signedRev := pond.SignedRevocation{
		Revocation: rev,
		Signature:  sig[:],
	}

	request := &pond.Request{
		Revocation: &signedRev,
	}

	out := &queuedMessage{
		revocation: true,
		request:    request,
		id:         c.randId(),
		server:     c.server, // revocations always go to the home server.
		created:    time.Now(),
	}
	c.enqueue(out)
	c.outbox = append(c.outbox, out)
	return out
}

func decryptMessage(sealed []byte, from *Contact) ([]byte, bool) {
	if from.ratchet != nil {
		plaintext, err := from.ratchet.Decrypt(sealed)
		if err != nil {
			return nil, false
		}
		return plaintext, true
	}

	var nonce [24]byte
	if len(sealed) < len(nonce) {
		return nil, false
	}
	copy(nonce[:], sealed)
	sealed = sealed[24:]
	headerLen := ephemeralBlockLen - len(nonce)
	if len(sealed) < headerLen {
		return nil, false
	}

	publicBytes, ok := decryptMessageInner(sealed[:headerLen], &nonce, from)
	if !ok || len(publicBytes) != 32 {
		return nil, false
	}
	var innerNonce [nonceLen]byte
	sealed = sealed[headerLen:]
	copy(innerNonce[:], sealed)
	sealed = sealed[nonceLen:]
	var ephemeralPublicKey [32]byte
	copy(ephemeralPublicKey[:], publicBytes)

	if plaintext, ok := box.Open(nil, sealed, &innerNonce, &ephemeralPublicKey, &from.lastDHPrivate); ok {
		return plaintext, ok
	}

	plaintext, ok := box.Open(nil, sealed, &innerNonce, &ephemeralPublicKey, &from.currentDHPrivate)
	if !ok {
		return nil, false
	}

	// They have clearly received our current DH value. Time to
	// rotate.
	copy(from.lastDHPrivate[:], from.currentDHPrivate[:])
	if _, err := io.ReadFull(rand.Reader, from.currentDHPrivate[:]); err != nil {
		panic(err)
	}
	return plaintext, true
}

func decryptMessageInner(sealed []byte, nonce *[24]byte, from *Contact) ([]byte, bool) {
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

func (c *client) processNewMessage(m NewMessage) {
	defer func() { m.ack <- true }()

	if m.fetched != nil {
		c.processFetch(m)
	} else {
		c.processServerAnnounce(m)
	}
}

func (c *client) processFetch(m NewMessage) {
	f := m.fetched

	sha := sha256.New()
	sha.Write(f.Message)
	digest := sha.Sum(nil)

	var tag []byte
	var ok bool
	if c.groupPriv.Verify(digest, sha, f.GroupSignature) {
		tag, ok = c.groupPriv.Open(f.GroupSignature)
	} else {
		found := false
		for _, prev := range c.prevGroupPrivs {
			if prev.priv.Verify(digest, sha, f.GroupSignature) {
				found = true
				tag, ok = c.groupPriv.Open(f.GroupSignature)
				break
			}
		}
		if !found {
			c.log.Errorf("Received message with bad group signature!")
			return
		}
	}
	if !ok {
		c.log.Errorf("Failed to open group signature!")
		return
	}

	var from *Contact
NextCandidate:
	for _, candidate := range c.contacts {
		if bytes.Equal(tag, candidate.groupKey.Tag()) {
			from = candidate
			break
		}
		for _, prevTag := range candidate.previousTags {
			if bytes.Equal(tag, prevTag.tag) {
				from = candidate
				break NextCandidate
			}
		}
	}

	if from == nil {
		c.log.Errorf("Message from unknown contact. Dropping. Tag: %x", tag)
		return
	}

	if from.revoked {
		// It's possible that there were pending messages from the
		// contact when we revoked them.
		c.log.Errorf("Message from revoked contact %s. Dropping", from.name)
		return
	}

	if len(f.Message) < box.Overhead+24 {
		c.logEvent(from, "Message too small to process")
		return
	}

	inboxMsg := &InboxMessage{
		id:           c.randId(),
		receivedTime: time.Now(),
		from:         from.id,
		sealed:       f.Message,
	}

	if !from.isPending {
		if !c.unsealMessage(inboxMsg, from) || len(inboxMsg.message.Body) == 0 {
			return
		}
	}

	c.inbox = append(c.inbox, inboxMsg)
	c.ui.processFetch(inboxMsg)
	c.save()

	c.receiveHook()

}

func (c *client) processServerAnnounce(m NewMessage) {
	inboxMsg := &InboxMessage{
		id:           c.randId(),
		receivedTime: time.Now(),
		from:         0,
		message:      m.announce.Message,
	}

	c.inbox = append(c.inbox, inboxMsg)
	c.ui.processServerAnnounce(inboxMsg)

	c.save()
}

func (c *client) unsealMessage(inboxMsg *InboxMessage, from *Contact) bool {
	if from.isPending {
		panic("was asked to unseal message from pending contact")
	}

	sealed := inboxMsg.sealed
	plaintext, ok := decryptMessage(sealed, from)

	if !ok {
		c.logEvent(from, "Failed to decrypt message")
		return false
	}

	if len(plaintext) < 4 {
		c.logEvent(from, "Plaintext too small to process")
		return false
	}

	mLen := int(binary.LittleEndian.Uint32(plaintext[:4]))
	plaintext = plaintext[4:]
	if mLen < 0 || mLen > len(plaintext) {
		c.logEvent(from, fmt.Sprintf("Plaintext length incorrect: %d", mLen))
		return false
	}
	plaintext = plaintext[:mLen]

	msg := new(pond.Message)
	if err := proto.Unmarshal(plaintext, msg); err != nil {
		c.logEvent(from, "Failed to parse message: "+err.Error())
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

	if from.ratchet == nil {
		if l := len(msg.MyNextDh); l != len(from.theirCurrentDHPublic) {
			c.logEvent(from, fmt.Sprintf("Bad Diffie-Hellman value length: %d", l))
			return false
		}

		if !bytes.Equal(from.theirCurrentDHPublic[:], msg.MyNextDh) {
			// We have a new DH value from them.
			copy(from.theirLastDHPublic[:], from.theirCurrentDHPublic[:])
			copy(from.theirCurrentDHPublic[:], msg.MyNextDh)
		}
	}

	var ackedIds []uint64
	ackedIds = append(ackedIds, msg.AlsoAck...)
	if msg.InReplyTo != nil {
		ackedIds = append(ackedIds, *msg.InReplyTo)
	}

	var now time.Time
	if len(ackedIds) > 0 {
		now = time.Now()
	}

	for _, ackedId := range ackedIds {
		for _, candidate := range c.outbox {
			if candidate.id == ackedId {
				candidate.acked = now
				c.ui.processAcknowledgement(candidate)
				break
			}
		}
	}

	if msg.SupportedVersion != nil {
		from.supportedVersion = *msg.SupportedVersion
	}

	from.kxsBytes = nil
	inboxMsg.message = msg
	inboxMsg.sealed = nil
	inboxMsg.read = false

	return true
}

func (c *client) processMessageSent(msr messageSendResult) {
	var msg *queuedMessage
	for _, m := range c.outbox {
		if m.id == msr.id {
			msg = m
			break
		}
	}

	if msg == nil {
		// Message might have been deleted while sending.
		return
	}

	if msr.revocation != nil {
		// We tried to deliver a message to a user but the server told
		// us that there's a pending revocation.
		to := c.contacts[msg.to]

		for revNum := 0; !to.revokedUs; revNum++ {
			var rev *pond.SignedRevocation
			if revNum == 0 {
				rev = msr.revocation
			} else {
				if n := revNum - 1; n < len(msr.extraRevocations) {
					rev = msr.extraRevocations[n]
				} else {
					break
				}
			}

			if gen := *rev.Revocation.Generation; gen != to.generation {
				c.log.Printf("Message to '%s' resulted in revocation for generation %d, but current generation is %d", to.name, gen, to.generation)
				return
			}

			// Check the signature on the revocation.
			revBytes, err := proto.Marshal(rev.Revocation)
			if err != nil {
				c.log.Printf("Failed to marshal revocation message: %s", err)
				return
			}

			var sig [ed25519.SignatureSize]byte
			if revSig := rev.Signature; copy(sig[:], revSig) != len(sig) {
				c.log.Printf("Bad signature length on revocation (%d bytes) from %s", len(revSig), to.name)
				return
			}

			var signed []byte
			signed = append(signed, revocationSignaturePrefix...)
			signed = append(signed, revBytes...)
			if !ed25519.Verify(&to.theirPub, signed, &sig) {
				c.log.Printf("Bad signature on revocation from %s", to.name)
				return
			}
			bbsRev, ok := new(bbssig.Revocation).Unmarshal(rev.Revocation.Revocation)
			if !ok {
				c.log.Printf("Failed to parse revocation from %s", to.name)
				return
			}
			to.generation++
			if !to.myGroupKey.Update(bbsRev) {
				// We were revoked.
				to.revokedUs = true
				// Further revocations will not be applied
				// because the loop conditional is false now.
				c.log.Printf("Revoked by %s", to.name)
				c.ui.processRevocationOfUs(to)

				// Mark all pending messages to this contact as
				// undeliverable.
				newQueue := make([]*queuedMessage, 0, len(c.queue))
				c.queueMutex.Lock()
				for _, m := range c.queue {
					if m.to != msg.to {
						newQueue = append(newQueue, m)
					}
				}
				c.queue = newQueue
				c.queueMutex.Unlock()
			} else {
				to.myGroupKey.Group.Update(bbsRev)
				// Outgoing messages will be resigned when the network
				// goroutine next attempts to send them.
			}

			c.ui.processRevocation(to)
		}

		return
	}

	msg.sent = time.Now()
	if msg.revocation {
		c.deleteOutboxMsg(msg.id)
		c.ui.removeOutboxMessageUI(msg)
	} else {
		c.ui.processMessageDelivered(msg)
	}
	c.save()
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

func (c *client) torDialer() proxy.Dialer {
	// We generate a random username so that Tor will decouple all of our
	// connections.
	var userBytes [8]byte
	c.randBytes(userBytes[:])
	auth := proxy.Auth{
		User:     base32.StdEncoding.EncodeToString(userBytes[:]),
		Password: "password",
	}
	dialer, err := proxy.SOCKS5("tcp", c.torAddress, &auth, proxy.Direct)
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

	serverIdentity, host, err := parseServer(server, c.dev)
	if err != nil {
		return nil, err
	}
	var tor proxy.Dialer
	if c.dev {
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

func (c *client) doCreateAccount(displayMsg func(string)) error {
	_, _, err := parseServer(c.server, c.dev)
	if err != nil {
		return err
	}

	if !c.dev {
		// Check that Tor is running.
		testConn, err := net.Dial("tcp", c.torAddress)
		if err != nil {
			return errors.New("Failed to connect to local Tor: " + err.Error())
		}
		testConn.Close()
	}

	displayMsg("Connecting...")

	conn, err := c.dialServer(c.server, false)
	if err != nil {
		return err
	}
	defer conn.Close()

	displayMsg("Requesting new account...")

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

	displayMsg("Done")

	return nil
}

// transactionRateSeconds is the mean of the exponential distribution that
// we'll sample in order to distribute the time between our network
// connections.
const transactionRateSeconds = 300 // five minutes

func (c *client) transact() {
	startup := true

	var ackChan chan bool
	var head *queuedMessage
	lastWasSend := false

	for {
		if head != nil {
			// We failed to send a message.
			c.queueMutex.Lock()
			head.sending = false
			c.queueMutex.Unlock()
			head = nil
		}

		if !startup || !c.autoFetch {
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
				delaySeconds := r.ExpFloat64() * transactionRateSeconds
				if c.dev {
					delaySeconds = 5
				}
				delay := time.Duration(delaySeconds*1000) * time.Millisecond
				c.log.Printf("Next network transaction in %s seconds", delay)
				timerChan = time.After(delay)
			}

			var ok bool
			select {
			case ackChan, ok = <-c.fetchNowChan:
				if !ok {
					return
				}
				c.log.Printf("Starting fetch because of fetchNow signal")
			case <-timerChan:
				c.log.Printf("Starting fetch because of timer")
			}
		}
		startup = false

		var req *pond.Request
		var server string

		useAnonymousIdentity := true
		isFetch := false
		c.queueMutex.Lock()
		if (!c.testing && lastWasSend) || len(c.queue) == 0 {
			useAnonymousIdentity = false
			isFetch = true
			req = &pond.Request{Fetch: &pond.Fetch{}}
			server = c.server
			c.log.Printf("Starting fetch from home server")
			lastWasSend = false
		} else {
			head = c.queue[0]
			head.sending = true
			req = head.request
			server = head.server
			c.log.Printf("Starting message transmission to %s", server)

			if head.revocation {
				useAnonymousIdentity = false
			}
			lastWasSend = true
		}
		c.queueMutex.Unlock()

		// Poke the UI thread so that it knows that a message has
		// started sending.
		c.messageSentChan <- messageSendResult{}

		conn, err := c.dialServer(server, useAnonymousIdentity)
		if err != nil {
			c.log.Printf("Failed to connect to %s: %s", server, err)
			continue
		}
		if lastWasSend && req == nil {
			resultChan := make(chan *pond.Request, 1)
			c.signingRequestChan <- signingRequest{head, resultChan}
			req = <-resultChan
			if req == nil {
				conn.Close()
				continue
			}
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

		conn.Close()

		if !isFetch {
			c.queueMutex.Lock()
			// Find the index of the message that we just sent (if any) in
			// the queue. It should be at the front, but something
			// may have happened while we didn't hold the lock.
			indexOfSentMessage := c.indexOfQueuedMessage(head)

			// If we sent a message that was removed from the queue while
			// we were processing it then ignore any result.
			if indexOfSentMessage == -1 {
				continue
			}

			head.sending = false

			if reply.Status == nil {
				c.removeQueuedMessage(indexOfSentMessage)
				c.queueMutex.Unlock()
				c.messageSentChan <- messageSendResult{id: head.id}
			} else {
				// If the send failed for any reason then we
				// want to move the message to the end of the
				// queue so that we never clog the queue with
				// an unsendable message. However, we also
				// don't want to reorder messages so all
				// messages to the same contact are moved to
				// the end of the queue.
				c.moveContactsMessagesToEndOfQueue(head.to)
				c.queueMutex.Unlock()

				if *reply.Status == pond.Reply_GENERATION_REVOKED && reply.Revocation != nil {
					c.messageSentChan <- messageSendResult{id: head.id, revocation: reply.Revocation, extraRevocations: reply.ExtraRevocations}
				}
			}

			head = nil
		} else if reply.Fetched != nil || reply.Announce != nil {
			ackChan := make(chan bool)
			c.newMessageChan <- NewMessage{reply.Fetched, reply.Announce, ackChan}
			<-ackChan
		}

		if err := replyToError(reply); err != nil {
			c.log.Errorf("Error from server %s: %s", server, err)
			continue
		}
	}
}

// detachmentTransfer is the interface to either an upload or download so that
// the code for moving the bytes can be shared between them.
type detachmentTransfer interface {
	// Request returns the request that should be sent to the server.
	Request() *pond.Request
	// ProcessReply returns a file to read/write from, the starting offset
	// for the transfer and the total size of the file. The file will
	// already have been positioned correctly.
	ProcessReply(*pond.Reply) (file *os.File, isUpload bool, offset, total int64, isComplete bool, err error)
	// Complete is called once the bytes have been transfered. It trues true on success.
	Complete(conn *transport.Conn) bool
}

type uploadTransfer struct {
	id    uint64
	file  *os.File
	total int64
}

func (ut uploadTransfer) Request() *pond.Request {
	return &pond.Request{
		Upload: &pond.Upload{
			Id:   proto.Uint64(ut.id),
			Size: proto.Int64(ut.total),
		},
	}
}

func (ut uploadTransfer) ProcessReply(reply *pond.Reply) (file *os.File, isUpload bool, offset, total int64, isComplete bool, err error) {
	if reply.Upload != nil && reply.Upload.Resume != nil {
		offset = *reply.Upload.Resume
	}

	if offset == ut.total {
		isComplete = true
		return
	}
	if offset > ut.total {
		err = fmt.Errorf("offset from server is greater than the length of the file: %d vs %d", offset, ut.total)
		return
	}
	pos, err := ut.file.Seek(offset, 0 /* from start */)
	if err != nil || pos != offset {
		err = fmt.Errorf("failed to seek in temp file: %d %d %s", pos, offset, err)
		return
	}

	file = ut.file
	isUpload = true
	total = ut.total
	return
}

func (ut uploadTransfer) Complete(conn *transport.Conn) bool {
	// The server will send us a zero byte if it got everything.
	buf := []byte{1}
	io.ReadFull(conn, buf)
	return buf[0] == 0
}

func (c *client) uploadDetachment(out chan interface{}, in *os.File, id uint64, killChan chan bool) error {
	transfer := uploadTransfer{file: in, id: id}

	fi, err := in.Stat()
	if err != nil {
		return err
	}
	transfer.total = fi.Size()

	return c.transferDetachment(out, c.server, transfer, id, killChan)
}

type downloadTransfer struct {
	fileID uint64
	file   *os.File
	resume int64
	from   *[32]byte
}

func (dt *downloadTransfer) Request() *pond.Request {
	pos, err := dt.file.Seek(0, 2 /* from end */)
	if err == nil {
		dt.resume = pos
	} else {
		dt.resume = 0
	}

	var resume *int64
	if dt.resume > 0 {
		resume = proto.Int64(dt.resume)
	}

	return &pond.Request{
		Download: &pond.Download{
			From:   dt.from[:],
			Id:     proto.Uint64(dt.fileID),
			Resume: resume,
		},
	}
}

func (dt *downloadTransfer) ProcessReply(reply *pond.Reply) (file *os.File, isUpload bool, offset, total int64, isComplete bool, err error) {
	if reply.Download == nil {
		err = errors.New("Reply from server didn't include a download section")
		return
	}

	total = *reply.Download.Size
	if total < dt.resume {
		err = errors.New("Reply from server suggested that the file was truncated")
		return
	}

	offset = dt.resume
	file = dt.file
	return
}

func (dt *downloadTransfer) Complete(conn *transport.Conn) bool {
	return true
}

func (c *client) downloadDetachment(out chan interface{}, file *os.File, id uint64, downloadURL string, killChan chan bool) error {
	c.log.Printf("Starting download of %s", downloadURL)
	u, err := url.Parse(downloadURL)
	if err != nil {
		return errors.New("failed to parse download URL: " + err.Error())
	}
	if u.Scheme != "pondserver" {
		return errors.New("download URL is a not a Pond URL")
	}
	path := u.Path
	if len(path) == 0 {
		return errors.New("download URL is missing a path")
	}
	path = path[1:]
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		return errors.New("download URL has incorrect number of path elements")
	}
	fromSlice, err := hex.DecodeString(parts[0])
	if err != nil {
		return errors.New("failed to parse public identity from download URL: " + err.Error())
	}
	if len(fromSlice) != 32 {
		return errors.New("public identity in download URL is wrong length")
	}
	var from [32]byte
	copy(from[:], fromSlice)

	fileID, err := strconv.ParseUint(parts[1], 16, 64)
	if err != nil {
		return errors.New("failed to parse download ID from URL: " + err.Error())
	}

	u.Path = ""
	server := u.String()

	transfer := &downloadTransfer{file: file, fileID: fileID, from: &from}

	return c.transferDetachment(out, server, transfer, id, killChan)
}

// transferDetachmentConn transfers as much of a detachment as possible on a
// single connection. It calls sendStatus repeatedly with the current state of
// the transfer and watches killChan for an abort signal. It returns an error
// and an indication of whether the error is fatal. If not fatatl then another
// connection can be attempted in order to resume the transfer.
func (c *client) transferDetachmentConn(sendStatus func(s string, done, total int64), conn *transport.Conn, transfer detachmentTransfer, killChan chan bool) (err error, fatal bool) {
	defer conn.Close()

	// transferred is the number of bytes that *this connection* has transferred.
	// total is the full length of the file.
	var startingOffset, transferred, total int64

	sendStatus("Requesting transfer", 0, 0)
	if err := conn.WriteProto(transfer.Request()); err != nil {
		return fmt.Errorf("failed to write request: %s", err), false
	}

	reply := new(pond.Reply)
	if err := conn.ReadProto(reply); err != nil {
		return fmt.Errorf("failed to read reply: %s", err), false
	}

	if reply.Status != nil && *reply.Status == pond.Reply_RESUME_PAST_END_OF_FILE {
		return nil, false
	}

	if err := replyToError(reply); err != nil {
		if reply.GetStatus() == pond.Reply_OVER_QUOTA {
			return fmt.Errorf("server reports that the upload would exceed allowed quota"), true
		}
		return fmt.Errorf("request failed: %s", err), false
	}

	var file *os.File
	var isUpload, isComplete bool
	if file, isUpload, startingOffset, total, isComplete, err = transfer.ProcessReply(reply); err != nil {
		return fmt.Errorf("request failed: %s", err), false
	}
	if isComplete {
		return nil, false
	}
	todo := total - startingOffset

	var in io.Reader
	var out io.Writer
	if isUpload {
		out = conn
		in = file
	} else {
		out = file
		in = conn
	}

	buf := make([]byte, 16*1024)
	var lastUpdate time.Time

	for transferred < todo {
		select {
		case <-killChan:
			return backgroundCanceledError, true
		default:
			break
		}

		conn.SetDeadline(time.Now().Add(30 * time.Second))

		n, err := in.Read(buf)
		if err != nil {
			if isUpload {
				return fmt.Errorf("failed to read from disk: %s", err), true
			}

			return err, false
		}

		n, err = out.Write(buf[:n])
		if err != nil {
			if !isUpload {
				return fmt.Errorf("failed to write to disk: %s", err), true
			}

			return err, false
		}

		transferred += int64(n)

		if transferred > todo {
			return errors.New("transferred more than the expected amount"), true
		}
		now := time.Now()
		if lastUpdate.IsZero() || now.Sub(lastUpdate) > 10*time.Millisecond {
			lastUpdate = now
			sendStatus("", startingOffset+transferred, total)
		}
	}
	sendStatus("", startingOffset+transferred, total)

	if transferred < todo {
		return errors.New("incomplete transfer"), false
	}

	if !transfer.Complete(conn) {
		return errors.New("didn't receive confirmation from server"), false
	}
	return nil, false
}

func (c *client) transferDetachment(out chan interface{}, server string, transfer detachmentTransfer, id uint64, killChan chan bool) error {
	sendStatus := func(s string, done, total int64) {
		select {
		case out <- DetachmentProgress{
			id:     id,
			done:   uint64(done),
			total:  uint64(total),
			status: s,
		}:
			break
		default:
		}
	}

	const initialBackoff = 10 * time.Second
	const maxBackoff = 5 * time.Minute
	backoff := initialBackoff

	const maxTransientErrors = 15
	transientErrors := 0

	for transientErrors < maxTransientErrors {
		sendStatus("Connecting", 0, 0)

		conn, err := c.dialServer(server, false)
		if err != nil {
			c.log.Printf("Failed to connect to %s: %s", server, err)
			sendStatus("Waiting to reconnect", 0, 0)

			select {
			case <-time.After(backoff):
				break
			case <-killChan:
				return backgroundCanceledError
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		backoff = initialBackoff
		err, isFatal := c.transferDetachmentConn(sendStatus, conn, transfer, killChan)
		if err == nil {
			c.log.Printf("Completed transfer to/from %s", server)
			return nil
		}

		if err == backgroundCanceledError {
			return err
		}

		if isFatal {
			err = fmt.Errorf("fatal error: %s", err)
		} else {
			transientErrors++
			err = fmt.Errorf("transient error: %s", err)
		}
		c.log.Printf("While transferring to/from %s: %s", server, err)
		if isFatal {
			return err
		}
	}

	err := errors.New("too many transient errors")
	c.log.Printf("While tranferring to/from %s: %s", server, err)
	return err
}
