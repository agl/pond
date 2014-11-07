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

// erasureRotationTime is the amount of time that we'll use a single erasure
// storage value before rotating.
const erasureRotationTime = 24 * time.Hour

func (c *client) loadState(stateFile *disk.StateFile, pw string) error {
	parsedState, err := stateFile.Read(pw)
	if err != nil {
		return err
	}
	return c.unmarshal(parsedState)
}

func (c *client) save() {
	c.log.Printf("Saving state")
	now := c.Now()
	rotateErasureStorage := now.Before(c.lastErasureStorageTime) || now.Sub(c.lastErasureStorageTime) > erasureRotationTime
	if rotateErasureStorage {
		c.log.Printf("Rotating erasure storage key")
		c.lastErasureStorageTime = now
	}
	serialized := c.marshal()
	c.writerChan <- disk.NewState{serialized, rotateErasureStorage, false /* don't destruct */}
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

	if state.LastErasureStorageTime != nil {
		c.lastErasureStorageTime = time.Unix(*state.LastErasureStorageTime, 0)
	}

	for _, prevGroupPriv := range state.PreviousGroupPrivateKeys {
		group, ok := new(bbssig.Group).Unmarshal(prevGroupPriv.Group)
		if !ok {
			return errors.New("client: failed to unmarshal previous group")
		}
		priv, ok := new(bbssig.PrivateKey).Unmarshal(group, prevGroupPriv.GroupPrivate)
		if !ok {
			return errors.New("client: failed to unmarshal previous group private key")
		}
		c.prevGroupPrivs = append(c.prevGroupPrivs, previousGroupPrivateKey{
			priv:    priv,
			expired: time.Unix(*prevGroupPriv.Expired, 0),
		})
	}

	for _, cont := range state.Contacts {
		contact := &Contact{
			id:               *cont.Id,
			name:             *cont.Name,
			kxsBytes:         cont.KeyExchangeBytes,
			pandaKeyExchange: cont.PandaKeyExchange,
			pandaResult:      cont.GetPandaError(),
			revokedUs:        cont.GetRevokedUs(),
		}
		c.registerId(contact.id)
		c.contacts[contact.id] = contact
		if contact.groupKey, ok = new(bbssig.MemberKey).Unmarshal(c.groupPriv.Group, cont.GroupKey); !ok {
			return errors.New("client: failed to unmarshal group member key")
		}
		copy(contact.lastDHPrivate[:], cont.LastPrivate)
		copy(contact.currentDHPrivate[:], cont.CurrentPrivate)

		if cont.Ratchet != nil {
			contact.ratchet = c.newRatchet(contact)
			if err := contact.ratchet.Unmarshal(cont.Ratchet); err != nil {
				return err
			}
		}

		if cont.IntroducedBy != nil {
			contact.introducedBy = *cont.IntroducedBy
		}
		if cont.VerifiedBy != nil && len(cont.VerifiedBy) > 0 {
			contact.verifiedBy = cont.VerifiedBy
		}
		if cont.IntroducedTo != nil && len(cont.IntroducedTo) > 0 {
			contact.introducedTo = cont.IntroducedTo
		}

		if cont.IsPending != nil && *cont.IsPending {
			contact.isPending = true
		}

		if len(cont.TheirIdentityPublic) != len(contact.theirIdentityPublic) && !contact.isPending {
			return errors.New("client: contact missing identity public key")
		}
		copy(contact.theirIdentityPublic[:], cont.TheirIdentityPublic)

		if contact.isPending == true { continue }

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

		copy(contact.theirLastDHPublic[:], cont.TheirLastPublic)
		copy(contact.theirCurrentDHPublic[:], cont.TheirCurrentPublic)

		for _, prevTag := range cont.PreviousTags {
			contact.previousTags = append(contact.previousTags, previousTag{
				tag:     prevTag.Tag,
				expired: time.Unix(*prevTag.Expired, 0),
			})
		}

		// For now we'll have to do this conditionally until everyone
		// has updated local state.
		if cont.Generation != nil {
			contact.generation = *cont.Generation
		}
		if cont.SupportedVersion != nil {
			contact.supportedVersion = *cont.SupportedVersion
		}

		contact.events = make([]Event, 0, len(cont.Events))
		for _, evt := range cont.Events {
			event := Event{
				t:   time.Unix(*evt.Time, 0),
				msg: *evt.Message,
			}
			contact.events = append(contact.events, event)
		}
	}

	now := c.Now()
	for _, m := range state.Inbox {
		msg := &InboxMessage{
			id:           *m.Id,
			from:         *m.From,
			receivedTime: time.Unix(*m.ReceivedTime, 0),
			acked:        *m.Acked,
			read:         *m.Read,
			sealed:       m.Sealed,
			retained:     m.GetRetained(),
			exposureTime: now,
		}
		c.registerId(msg.id)
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
		c.registerId(msg.id)
		if len(m.Message) > 0 {
			msg.message = new(pond.Message)
			if err := proto.Unmarshal(m.Message, msg.message); err != nil {
				return errors.New("client: corrupt message in outbox: " + err.Error())
			}
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
		msg.revocation = m.GetRevocation()
		if msg.revocation && len(msg.server) == 0 {
			// There was a bug in some versions where revoking a
			// pending contact would result in a revocation message
			// with an empty server.
			msg.server = c.server
		}

		c.outbox = append(c.outbox, msg)

		if msg.sent.IsZero() && (msg.to == 0 || !c.contacts[msg.to].revokedUs) {
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
		c.registerId(draft.id)
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
			SupportedVersion: proto.Int32(contact.supportedVersion),
			PandaKeyExchange: contact.pandaKeyExchange,
			PandaError:       proto.String(contact.pandaResult),
			RevokedUs:        proto.Bool(contact.revokedUs),
			IntroducedBy:     proto.Uint64(contact.introducedBy),
			IntroducedTo:     contact.introducedTo,
			VerifiedBy:       contact.verifiedBy,
		}

		cont.TheirIdentityPublic = contact.theirIdentityPublic[:]
		if !contact.isPending {
			cont.MyGroupKey = contact.myGroupKey.Marshal()
			cont.TheirGroup = contact.myGroupKey.Group.Marshal()
			cont.TheirServer = proto.String(contact.theirServer)
			cont.TheirPub = contact.theirPub[:]
			cont.Generation = proto.Uint32(contact.generation)

			cont.TheirLastPublic = contact.theirLastDHPublic[:]
			cont.TheirCurrentPublic = contact.theirCurrentDHPublic[:]
		}
		if contact.ratchet != nil {
			cont.Ratchet = contact.ratchet.Marshal(time.Now(), messageLifetime)
		}
		for _, prevTag := range contact.previousTags {
			if time.Since(prevTag.expired) > previousTagLifetime {
				continue
			}
			cont.PreviousTags = append(cont.PreviousTags, &disk.Contact_PreviousTag{
				Tag:     prevTag.tag,
				Expired: proto.Int64(prevTag.expired.Unix()),
			})
		}
		cont.Events = make([]*disk.Contact_Event, 0, len(contact.events))
		for _, event := range contact.events {
			if time.Since(event.t) > messageLifetime {
				continue
			}
			cont.Events = append(cont.Events, &disk.Contact_Event{
				Time:    proto.Int64(event.t.Unix()),
				Message: proto.String(event.msg),
			})
		}
		contacts = append(contacts, cont)
	}

	var inbox []*disk.Inbox
	for _, msg := range c.inbox {
		if time.Since(msg.receivedTime) > messageLifetime && !msg.retained {
			continue
		}
		m := &disk.Inbox{
			Id:           proto.Uint64(msg.id),
			From:         proto.Uint64(msg.from),
			ReceivedTime: proto.Int64(msg.receivedTime.Unix()),
			Acked:        proto.Bool(msg.acked),
			Read:         proto.Bool(msg.read),
			Sealed:       msg.sealed,
			Retained:     proto.Bool(msg.retained),
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
			Id:         proto.Uint64(msg.id),
			To:         proto.Uint64(msg.to),
			Server:     proto.String(msg.server),
			Created:    proto.Int64(msg.created.Unix()),
			Revocation: proto.Bool(msg.revocation),
		}
		if msg.message != nil {
			if m.Message, err = proto.Marshal(msg.message); err != nil {
				panic(err)
			}
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
		Private:                c.priv[:],
		Public:                 c.pub[:],
		Identity:               c.identity[:],
		Server:                 proto.String(c.server),
		Group:                  c.groupPriv.Group.Marshal(),
		GroupPrivate:           c.groupPriv.Marshal(),
		Generation:             proto.Uint32(c.generation),
		Contacts:               contacts,
		Inbox:                  inbox,
		Outbox:                 outbox,
		Drafts:                 drafts,
		LastErasureStorageTime: proto.Int64(c.lastErasureStorageTime.Unix()),
	}
	for _, prevGroupPriv := range c.prevGroupPrivs {
		if time.Since(prevGroupPriv.expired) > previousTagLifetime {
			continue
		}

		state.PreviousGroupPrivateKeys = append(state.PreviousGroupPrivateKeys, &disk.State_PreviousGroup{
			Group:        prevGroupPriv.priv.Group.Marshal(),
			GroupPrivate: prevGroupPriv.priv.Marshal(),
			Expired:      proto.Int64(prevGroupPriv.expired.Unix()),
		})
	}
	s, err := proto.Marshal(state)
	if err != nil {
		panic(err)
	}
	return s
}
