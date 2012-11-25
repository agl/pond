package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"time"

	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/go.crypto/scrypt"
	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/pond/bbssig"
	"github.com/agl/pond/client/protos"
	pond "github.com/agl/pond/protos"
)

func (c *client) deriveKey(pw string) ([]byte, error) {
	return scrypt.Key([]byte(pw), c.diskSalt[:], 32768, 16, 1, 32)
}

func (c *client) save() {
	c.log.Printf("Saving state")
	serialized := c.marshal()
	c.writerChan <- serialized
}

func (c *client) unmarshal(state *protos.State) error {
	c.server = *state.Server

	if len(state.Identity) != len(c.identity) {
		return errors.New("client: identity is wrong length in State")
	}
	copy(c.identity[:], state.Identity)
	curve25519.ScalarBaseMult(&c.identityPublic, &c.identity)

	group, ok := new(bbssig.Group).Unmarshal(state.Group)
	if !ok {
		return errors.New("client: failed to unmarshal group")
	}
	c.groupPriv, ok = new(bbssig.PrivateKey).Unmarshal(group, state.GroupPrivate)
	if !ok {
		return errors.New("client: failed to unmarshal group private key")
	}

	if len(state.Private) != len(c.priv) {
		return errors.New("client: failed to unmarshal private key")
	}
	copy(c.priv[:], state.Private)
	if len(state.Public) != len(c.pub) {
		return errors.New("client: failed to unmarshal public key")
	}
	copy(c.pub[:], state.Public)
	c.generation = *state.Generation

	for _, cont := range state.Contacts {
		contact := &Contact{
			id:       *cont.Id,
			name:     *cont.Name,
			kxsBytes: cont.KeyExchangeBytes,
		}
		c.contacts[contact.id] = contact
		if contact.groupKey, ok = new(bbssig.MemberKey).Unmarshal(c.groupPriv.Group, cont.GroupKey); !ok {
			return errors.New("client: failed to unmarshal group member key")
		}
		copy(contact.lastDHPrivate[:], cont.LastPrivate)
		copy(contact.currentDHPrivate[:], cont.CurrentPrivate)
		if cont.IsPending != nil && *cont.IsPending {
			contact.isPending = true
			continue
		}

		theirGroup, ok := new(bbssig.Group).Unmarshal(cont.TheirGroup)
		if !ok {
			return errors.New("client: failed to unmarshal their group")
		}
		if contact.myGroupKey, ok = new(bbssig.MemberKey).Unmarshal(theirGroup, cont.MyGroupKey); !ok {
			return errors.New("client: failed to unmarshal my group key")
		}

		if cont.TheirServer == nil {
			return errors.New("client: contact missing server")
		}
		contact.theirServer = *cont.TheirServer

		if len(cont.TheirPub) != len(contact.theirPub) {
			return errors.New("client: contact missing public key")
		}
		copy(contact.theirPub[:], cont.TheirPub)

		if len(cont.TheirIdentityPublic) != len(contact.theirIdentityPublic) {
			return errors.New("client: contact missing identity public key")
		}
		copy(contact.theirIdentityPublic[:], cont.TheirIdentityPublic)

		copy(contact.theirLastDHPublic[:], cont.TheirLastPublic)
		copy(contact.theirCurrentDHPublic[:], cont.TheirCurrentPublic)

		contact.generation = *cont.Generation
	}

	for _, m := range state.Inbox {
		msg := &InboxMessage{
			id:           *m.Id,
			from:         *m.From,
			receivedTime: time.Unix(*m.ReceivedTime, 0),
			acked:        *m.Acked,
			read:         *m.Read,
			sealed:       m.Sealed,
		}
		if len(m.Message) > 0 {
			msg.message = new(pond.Message)
			if err := proto.Unmarshal(m.Message, msg.message); err != nil {
				return errors.New("client: corrupt message in inbox: " + err.Error())
			}
		}

		c.inbox = append(c.inbox, msg)
	}

	for _, m := range state.Outbox {
		msg := &queuedMessage{
			id:      *m.Id,
			to:      *m.To,
			server:  *m.Server,
			created: time.Unix(*m.Created, 0),
		}
		msg.message = new(pond.Message)
		if err := proto.Unmarshal(m.Message, msg.message); err != nil {
			return errors.New("client: corrupt message in outbox: " + err.Error())
		}
		if m.Sent != nil {
			msg.sent = time.Unix(*m.Sent, 0)
		}
		if m.Acked != nil {
			msg.acked = time.Unix(*m.Acked, 0)
		}
		if len(m.Request) != 0 {
			msg.request = new(pond.Request)
			if err := proto.Unmarshal(m.Request, msg.request); err != nil {
				return errors.New("client: corrupt request in outbox: " + err.Error())
			}
		}

		c.outbox = append(c.outbox, msg)

		if msg.sent.IsZero() {
			// This message hasn't been sent yet.
			c.enqueue(msg)
		}
	}

	return nil
}

func (c *client) marshal() []byte {
	var err error
	var contacts []*protos.Contact

	for _, contact := range c.contacts {
		cont := &protos.Contact{
			Id:               proto.Uint64(contact.id),
			Name:             proto.String(contact.name),
			GroupKey:         contact.groupKey.Marshal(),
			IsPending:        proto.Bool(contact.isPending),
			KeyExchangeBytes: contact.kxsBytes,
			LastPrivate:      contact.lastDHPrivate[:],
			CurrentPrivate:   contact.currentDHPrivate[:],
		}
		if !contact.isPending {
			cont.MyGroupKey = contact.myGroupKey.Marshal()
			cont.TheirGroup = contact.myGroupKey.Group.Marshal()
			cont.TheirServer = proto.String(contact.theirServer)
			cont.TheirPub = contact.theirPub[:]
			cont.TheirIdentityPublic = contact.theirIdentityPublic[:]
			cont.TheirLastPublic = contact.theirLastDHPublic[:]
			cont.TheirCurrentPublic = contact.theirCurrentDHPublic[:]
			cont.Generation = proto.Uint32(contact.generation)
		}
		contacts = append(contacts, cont)
	}

	var inbox []*protos.Inbox
	for _, msg := range c.inbox {
		if time.Since(msg.receivedTime) > messageLifetime {
			continue
		}
		m := &protos.Inbox{
			Id:           proto.Uint64(msg.id),
			From:         proto.Uint64(msg.from),
			ReceivedTime: proto.Int64(msg.receivedTime.Unix()),
			Acked:        proto.Bool(msg.acked),
			Read:         proto.Bool(msg.read),
			Sealed:       msg.sealed,
		}
		if msg.message != nil {
			if m.Message, err = proto.Marshal(msg.message); err != nil {
				panic(err)
			}
		}
		inbox = append(inbox, m)
	}

	var outbox []*protos.Outbox
	for _, msg := range c.outbox {
		if time.Since(msg.created) > messageLifetime {
			continue
		}
		m := &protos.Outbox{
			Id:      proto.Uint64(msg.id),
			To:      proto.Uint64(msg.to),
			Server:  proto.String(msg.server),
			Created: proto.Int64(msg.created.Unix()),
		}
		if m.Message, err = proto.Marshal(msg.message); err != nil {
			panic(err)
		}
		if !msg.sent.IsZero() {
			m.Sent = proto.Int64(msg.sent.Unix())
		}
		if !msg.acked.IsZero() {
			m.Acked = proto.Int64(msg.acked.Unix())
		}
		if msg.request != nil {
			if m.Request, err = proto.Marshal(msg.request); err != nil {
				panic(err)
			}
		}

		outbox = append(outbox, m)
	}

	state := &protos.State{
		Private:      c.priv[:],
		Public:       c.pub[:],
		Identity:     c.identity[:],
		Server:       proto.String(c.server),
		Group:        c.groupPriv.Group.Marshal(),
		GroupPrivate: c.groupPriv.Marshal(),
		Generation:   proto.Uint32(c.generation),
		Contacts:     contacts,
		Inbox:        inbox,
		Outbox:       outbox,
	}
	s, err := proto.Marshal(state)
	if err != nil {
		panic(err)
	}
	return s
}

const sCryptSaltLen = 32
const diskSaltLen = 32
const smearedCopies = 32768 / 24

func getSCryptSaltFromState(state []byte) ([32]byte, bool) {
	var salt [32]byte
	if len(state) < sCryptSaltLen {
		return salt, false
	}
	copy(salt[:], state)
	return salt, true
}

func stateWriter(stateFilename string, key *[32]byte, salt *[sCryptSaltLen]byte, states chan []byte, done chan bool) {
	for {
		s, ok := <-states
		if !ok {
			close(done)
			return
		}

		length := uint32(len(s)) + 4
		for i := uint(17); i < 32; i++ {
			if n := (uint32(1) << i); n >= length {
				length = n
				break
			}
		}

		plaintext := make([]byte, length)
		copy(plaintext[4:], s)
		if _, err := io.ReadFull(rand.Reader, plaintext[len(s)+4:]); err != nil {
			panic(err)
		}
		binary.LittleEndian.PutUint32(plaintext, uint32(len(s)))

		var nonceSmear [24 * smearedCopies]byte
		if _, err := io.ReadFull(rand.Reader, nonceSmear[:]); err != nil {
			panic(err)
		}

		var nonce [24]byte
		for i := 0; i < smearedCopies; i++ {
			for j := 0; j < 24; j++ {
				nonce[j] ^= nonceSmear[24*i+j]
			}
		}

		ciphertext := secretbox.Seal(nil, plaintext, &nonce, key)

		out, err := os.Create(stateFilename)
		if err != nil {
			panic(err)
		}
		if _, err := out.Write(salt[:]); err != nil {
			panic(err)
		}
		if _, err := out.Write(nonceSmear[:]); err != nil {
			panic(err)
		}
		if _, err := out.Write(ciphertext); err != nil {
			panic(err)
		}
		out.Close()
	}
}

var badPasswordError = errors.New("bad password")

func (c *client) loadState(b []byte, key *[32]byte) error {
	if len(b) < sCryptSaltLen+24*smearedCopies {
		return errors.New("state file is too small to be valid")
	}

	b = b[sCryptSaltLen:]

	var nonce [24]byte
	for i := 0; i < smearedCopies; i++ {
		for j := 0; j < 24; j++ {
			nonce[j] ^= b[24*i+j]
		}
	}

	b = b[24*smearedCopies:]
	plaintext, ok := secretbox.Open(nil, b, &nonce, key)
	if !ok {
		return badPasswordError
	}
	if len(plaintext) < 4 {
		return errors.New("state file corrupt")
	}
	length := binary.LittleEndian.Uint32(plaintext[:4])
	plaintext = plaintext[4:]
	if length > 1<<31 || length > uint32(len(plaintext)) {
		return errors.New("state file corrupt")
	}
	plaintext = plaintext[:int(length)]

	var state protos.State
	if err := proto.Unmarshal(plaintext, &state); err != nil {
		return err
	}

	if err := c.unmarshal(&state); err != nil {
		return err
	}
	return nil
}
