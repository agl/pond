package main

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"

	"github.com/agl/pond/panda"
	pond "github.com/agl/pond/protos"
	"github.com/golang/protobuf/proto"
)

const (
	disableDarkWebOfTrust     = 0xFFFFFFFFFFFFFFFF
	introducePandaMessageDesc = "\n---- Introduction URIs for proposed new contacts ----\n"
)

func addIdSet(set *[]uint64, id uint64) {
	for _, s := range *set {
		if s == id {
			return
		}
	}
	*set = append(*set, id)
}

func removeIdSet(set *[]uint64, id uint64) {
	for i, s := range *set {
		if s == id {
			*set = append((*set)[:i], (*set)[i+1:]...)
			return
		}
	}
}

func isInIdSet(set []uint64, id uint64) bool {
	for _, s := range set {
		if s == id {
			return true
		}
	}
	return false
}

func (c *client) contactListFromIdSet(set []uint64) (ci contactList) {
	for _, id := range set {
		ci = append(ci, c.contacts[id])
	}
	return
}

func contactListToIdSet(cl contactList) (set []uint64) {
	for _, cnt := range cl {
		addIdSet(&set, cnt.id)
	}
	return
}

func (contact *Contact) keepSocialGraphRecords() bool {
	return contact.introducedBy != disableDarkWebOfTrust
}

func (c *client) initSocialGraphRecords(contact *Contact) {
	// If all existing contacts have the Dark Web of Trust disabled then
	// new contacts should start with the Dark Web of Trust disabled too.
	if contact.introducedBy != 0 {
		return
	}
	if c.contacts == nil || len(c.contacts) == 0 {
		return
	}
	contact.introducedBy = disableDarkWebOfTrust
	for _, cnt := range c.contacts {
		if cnt.introducedBy != disableDarkWebOfTrust {
			contact.introducedBy = 0
			break
		}
	}
}

func (c *client) deleteSocialGraphRecords(id uint64) {
	for _, contact := range c.contacts {
		if contact.introducedBy == id {
			contact.introducedBy = 0
		}
		removeIdSet(&contact.verifiedBy, id)
		removeIdSet(&contact.introducedTo, id)
	}
}

// We could make this into a tagged union of a []pond.Message_Introduction
// and a uri string if we want to support older pond clients
type Introductions []*pond.Message_Introduction

func (c *client) introducePandaMessages_pair(cnt1, cnt2 *Contact, real bool) (Introductions, Introductions) {
	panda_secret := panda.NewSecretString(c.rand)[2:]
	intro := func(cnt *Contact) Introductions {
		i := &pond.Message_Introduction{
			Name:        proto.String(cnt.name),
			Identity:    cnt.theirIdentityPublic[:],
			PandaSecret: proto.String(panda_secret),
		}
		return Introductions{i}
		/*
			if new protocol version {
				... above code ...
			} else old protocol version {
				v := url.Values{
					"pandaSecret": {panda_secret},
					"identity":    {fmt.Sprintf("%x", cnt.theirIdentityPublic)},
				}
				u := url.URL{
					Scheme:   "pond-introduce",
					Opaque:   url.QueryEscape(cnt.name),
					RawQuery: v.Encode(),
				}
				i.uri = u.String() + "#"
			}
		*/
	}
	if real && cnt1.keepSocialGraphRecords() && cnt2.keepSocialGraphRecords() {
		addIdSet(&cnt1.introducedTo, cnt2.id)
		addIdSet(&cnt2.introducedTo, cnt1.id)
	}
	return intro(cnt2), intro(cnt1)
}

func (c *client) introducePandaMessages(shown, hidden contactList, real bool) ([]Introductions, []Introductions) {
	n := len(shown) + len(hidden)
	var intros []Introductions = make([]Introductions, n)
	cnts := append(shown, hidden...)
	for i := 0; i < len(shown); i++ {
		for j := i + 1; j < n; j++ {
			ui, uj := c.introducePandaMessages_pair(cnts[i], cnts[j], real)
			intros[i] = append(intros[i], ui...)
			intros[j] = append(intros[j], uj...)
		}
	}
	return intros[0:len(shown)], intros[len(shown):]
}

func (c *client) introducePandaMessages_onemany(cnts contactList, real bool) []Introductions {
	urls1, urls2 := c.introducePandaMessages(contactList{cnts[0]}, cnts[1:], real)
	return append(urls1, urls2...)
}

func (c *client) introducePandaMessages_group(cnts contactList, real bool) []Introductions {
	urls, _ := c.introducePandaMessages(cnts, nil, real)
	return urls
}

type ProposedContact struct {
	sharedSecret        string
	theirIdentityPublic [32]byte
	name                string
	id                  uint64 // zero if new or failed
	onGreet             func(*Contact)
}

type ProposedContacts []ProposedContact

func (s ProposedContacts) Len() int {
	return len(s)
}

func (s ProposedContacts) Less(i, j int) bool {
	return s[i].name < s[j].name
}

func (s ProposedContacts) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (c *client) fixProposedContactName(pc *ProposedContact, sender uint64) {
	// We should a fuzzy test for name similarity, maybe based on n-grams
	// or maybe a fast fuzzy spelling suggestion algorithm
	//   https://github.com/sajari/fuzzy
	// or even JaroWinkler or Levenshtein from
	// "github.com/antzucaro/matchr" here :
	//   https://godoc.org/github.com/antzucaro/matchr#JaroWinkler
	s := ""
	conflict0, ok := c.contactByName(pc.name)
	if !ok {
		return
	}
	i := 0
	for {
		s = fmt.Sprintf("/%d?", i)
		_, ok := c.contactByName(pc.name + s)
		if !ok {
			break
		}
		i++
	}
	c.log.Printf("Another contact is already named %s, appending '%s'.  Rename them, but make sure %s hasn't done anything nefarious here.",
		pc.name, s, c.contacts[sender].name)
	pc.name += s

	e := fmt.Sprintf("%s suggested the name %s for %s.",
		c.contacts[sender].name, conflict0.name, pc.name)
	if i := conflict0.introducedBy; i != 0 && i != disableDarkWebOfTrust {
		e += fmt.Sprintf(" Also %s was previously introduced by %s. Do you trust both %s and %s?",
			conflict0.name, c.contacts[i].name,
			c.contacts[sender].name, c.contacts[i].name)
	} else {
		e += fmt.Sprintf(" Do you trust %s?", c.contacts[i].name)
	}

	id0 := conflict0.id
	pc.onGreet = func(cnt1 *Contact) {
		c.logEvent(cnt1, e)
		logEvent := func(id uint64) {
			if cnt, ok := c.contacts[id]; ok {
				c.logEvent(cnt, e)
			} else {
				c.log.Printf("Failed logEvent : Contact involved in introduction was deleted?")
			}
		}
		logEvent(sender)
		logEvent(id0)
	}
}

func (c *client) checkProposedContact(pc *ProposedContact, sender uint64) {
	existing, found := c.contactByIdentity(pc.theirIdentityPublic[:])
	if found && c.contacts[sender].keepSocialGraphRecords() {
		pc.id = existing.id
		if existing.introducedBy != sender && existing.keepSocialGraphRecords() {
			addIdSet(&existing.verifiedBy, sender)
		}
	}
	if pc.name == "" {
		pc.name = fmt.Sprintf("%x", pc.theirIdentityPublic)
		c.log.Printf("Empty contact name, using identity %s.", pc.name)
	}

	if !found {
		c.fixProposedContactName(pc, sender)
	}
}

func parseKnownOpaqueURI(s string) (opaque string, vs url.Values, err error) {
	u, e := url.Parse(s)
	opaque = u.Opaque
	if e != nil {
		err = e
	} else {
		vs, err = url.ParseQuery(u.RawQuery)
	}
	return
}

func singletonValues(values url.Values) bool {
	for _, l := range values {
		if len(l) > 1 {
			return false
		}
	}
	return true
}

// Finds and parses all the pond-introduce URIs in a message body.
func (c *client) parsePandaURLs(sender uint64, body string) []ProposedContact {
	var l []ProposedContact
	re := regexp.MustCompile("pond-introduce:([^& ?#]+)\\?([^& ?#]+)(&([^& ?#]+))*")
	ms := re.FindAllString(body, -1) // -1 means find all
	for _, m := range ms {
		opaque, vs, err := parseKnownOpaqueURI(m)
		if err != nil || !singletonValues(vs) {
			c.log.Printf("Malformed pond-introduce: URI : %s", m)
			continue
		}

		var pc ProposedContact
		pc.name, err = url.QueryUnescape(opaque)
		if err != nil {
			c.log.Printf("Malformed pond-introduce: URI : %s", m)
			continue
		}

		pc.sharedSecret = vs.Get("pandaSecret")
		if !panda.IsAcceptableSecretString(pc.sharedSecret) {
			c.log.Printf("Unacceptably weak secret '%s' for %s, continuing.",
				pc.sharedSecret, pc.name)
		}

		identity := vs.Get("identity")
		if !hexDecodeSafe(pc.theirIdentityPublic[:], identity) || len(identity) != 64 {
			c.log.Printf("Bad public identity %s, skipping.", identity)
			continue
		}

		c.checkProposedContact(&pc, sender)
		l = append(l, pc)
	}
	return l
}

// Builds list of ProposedContacts from which to create greet contact buttons.
// We allow contacts to be added even if they fail most checks here because
// maybe they're the legit contact and the existing one is bad.
func (c *client) observeIntroductions(msg *InboxMessage) []ProposedContact {
	var l []ProposedContact
	// msg.message could be nil if we're in a half paired message situation
	if msg.message == nil {
		return l
	}

	for _, intro := range msg.message.Introductions {
		pc := ProposedContact{
			sharedSecret: *intro.PandaSecret,
			name:         *intro.Name,
		}

		if len(intro.Identity) != 32 {
			c.log.Printf("Bad public identity %x, skipping.", intro.Identity)
			continue
		}
		copy(pc.theirIdentityPublic[:], intro.Identity)

		c.checkProposedContact(&pc, msg.from)
		l = append(l, pc)
	}
	// We sort mostly just to keep the tests deterministic
	sort.Sort(ProposedContacts(l))

	return append(l, c.parsePandaURLs(msg.from, string(msg.message.Body))...)
}

// Add a ProposedContact using PANDA once by building panda.SharedSecret and
// the basic contact struct to call beginPandaKeyExchange.
func (c *client) beginProposedPandaKeyExchange(pc ProposedContact, introducedBy uint64) *Contact {
	if len(pc.sharedSecret) == 0 || !panda.IsAcceptableSecretString(pc.sharedSecret) {
		c.log.Printf("Unacceptably weak secret '%s'.", pc.sharedSecret)
		return nil
	}
	if pc.id != 0 {
		c.log.Printf("Attempted to add introduced contact %s, who is your existing contact %s, this is an internal error.\n", termPrefix,
			pc.name, c.contacts[pc.id].name)
		return nil
	}

	contact := &Contact{
		name:                pc.name,
		isPending:           true,
		id:                  c.randId(),
		theirIdentityPublic: pc.theirIdentityPublic,
	}
	// theirIdentityPublic is only set only for contacts pending by introduction
	if c.contacts[introducedBy].keepSocialGraphRecords() {
		contact.introducedBy = introducedBy
	} else {
		c.log.Printf("Introduced contact %s is not marked as introduced by %s because %s has keeping such records disabled.\n",
			pc.name, c.contacts[introducedBy].name, c.contacts[introducedBy].name)
	}
	if pc.onGreet != nil {
		pc.onGreet(contact)
	}

	stack := &panda.CardStack{
		NumDecks: 1,
	}
	secret := panda.SharedSecret{
		Secret: pc.sharedSecret,
		Cards:  *stack,
	}
	c.newKeyExchange(contact)
	c.beginPandaKeyExchange(contact, secret)
	return contact
}
