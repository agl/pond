package main

import (
	"errors"
	"time"

	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/pond/bbssig"
	"github.com/agl/pond/client/disk"
	pond "github.com/agl/pond/protos"
)

func (c *client) loadState(state []byte) error {
	parsedState, err := disk.LoadState(state, &c.diskKey)
	if err != nil {
		return err
	}
	return c.unmarshal(parsedState)
}

func (c *client) save() {
	c.log.Printf("Saving state")
	serialized := c.marshal()
	c.writerChan <- serialized
}

func (c *client) unmarshal(state *disk.State) error {
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

		// For now we'll have to do this conditionally until everyone
		// has updated local state.
		if cont.Generation != nil {
			contact.generation = *cont.Generation
		}
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

	for _, m := range state.Drafts {
		draft := &Draft{
			id:          *m.Id,
			body:        *m.Body,
			attachments: m.Attachments,
			detachments: m.Detachments,
			created:     time.Unix(*m.Created, 0),
		}
		if m.To != nil {
			draft.to = *m.To
		}
		if m.InReplyTo != nil {
			draft.inReplyTo = *m.InReplyTo
		}

		c.drafts[draft.id] = draft
	}

	return nil
}

func (c *client) marshal() []byte {
	var err error
	var contacts []*disk.Contact

	for _, contact := range c.contacts {
		cont := &disk.Contact{
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

	var inbox []*disk.Inbox
	for _, msg := range c.inbox {
		if time.Since(msg.receivedTime) > messageLifetime {
			continue
		}
		m := &disk.Inbox{
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

	var outbox []*disk.Outbox
	for _, msg := range c.outbox {
		if time.Since(msg.created) > messageLifetime {
			continue
		}
		m := &disk.Outbox{
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

	var drafts []*disk.Draft
	for _, draft := range c.drafts {
		m := &disk.Draft{
			Id:          proto.Uint64(draft.id),
			Body:        proto.String(draft.body),
			Attachments: draft.attachments,
			Detachments: draft.detachments,
			Created:     proto.Int64(draft.created.Unix()),
		}
		if draft.to != 0 {
			m.To = proto.Uint64(draft.to)
		}
		if draft.inReplyTo != 0 {
			m.InReplyTo = proto.Uint64(draft.inReplyTo)
		}

		drafts = append(drafts, m)
	}

	state := &disk.State{
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
		Drafts:       drafts,
	}
	s, err := proto.Marshal(state)
	if err != nil {
		panic(err)
	}
	return s
}
