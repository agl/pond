package main

import (
	"fmt"
	"net/url"
	"regexp"

	"github.com/agl/pond/panda"
)

const (
	introducePandaMessageDesc = "Introduction URLs for proposed new contacts :\n"
)

func (c *client) introducePandaMessages_pair(cnt1, cnt2 *Contact) (string, string) {
	panda_secret := panda.NewSecretString(c.rand)[2:]
	s := func(cnt *Contact) string {
		return fmt.Sprintf("pond-introduce-panda://%s/%s/%x/\n",
			url.QueryEscape(cnt.name), panda_secret,
			cnt.theirIdentityPublic) // no EncodeToString?
	}
	return s(cnt1), s(cnt2)
}

func (c *client) introducePandaMessages_onemany(cnts contactList) []string {
	var urls []string = make([]string, len(cnts))
	cnt1 := cnts[0]
	for i, cnt2 := range cnts[1:] {
		// if i==0 { continue }
		u1, u2 := c.introducePandaMessages_pair(cnt1, cnt2)
		urls[0] += u1
		urls[i] = u2
	}
	return urls
}

func (c *client) introducePandaMessages_group(cnts contactList) []string {
	n := len(cnts)
	var urls []string = make([]string, len(cnts))
	// for i := 0; i < n; i++ { urls[i] = "" }
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			ui, uj := c.introducePandaMessages_pair(cnts[i], cnts[j])
			urls[i] += ui
			urls[j] += uj
		}
	}
	return urls
}

func (c *client) introducePandaMessages_fancy(shown, hidden contactList) ([]string, []string) {
	n := len(shown) + len(hidden)
	var urls []string = make([]string, n)
	cnts := append(shown, hidden...)
	for i := 0; i < len(shown); i++ {
		for j := i + 1; j < n; j++ {
			ui, uj := c.introducePandaMessages_pair(cnts[i], cnts[j])
			urls[i] += ui
			urls[j] += uj
		}
	}
	return urls[0:len(shown)], urls[len(shown):]
}

// func introducePandaMessages_onemany(cnts contactList) ([]string) {
//	urls1,urls2 := introducePandaMessages_fancy({cnts[0]},cnts[1:])
//	return append(urls1,urls2...)
// }

// func introducePandaMessages_group(cnts contactList) ([]string) {
//	urls,_ := introducePandaMessages_fancy(cnts,nil)
//	return urls
// }

type ProposedContact struct {
	sharedSecret        string
	theirIdentityPublic [32]byte
	name                string
	id                  uint64 // zero if new or failed
}

func (c *client) checkProposedContactName(sender uint64, pc ProposedContact) {
	// We should consider using JaroWinkler or Levenshtein from
	// "github.com/antzucaro/matchr" here :
	//   https://godoc.org/github.com/antzucaro/matchr#JaroWinkler
	// Or maybe a fast fuzzy spelling suggestion algorithm
	//   https://github.com/sajari/fuzzy
	// for _, contact := range c.contacts { }
	// At least we now alphabatize the contacts listing however.
	s := ""
	_, ok := c.contactByName(pc.name)
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

	// if userlog {
	// 	e := fmt.Sprintf("%s suggested the name %s for %s.  Verify that nothing nefarious happened and rename them if desired.",
	//		c.contacts[sender].name,pc.name,c.contacts[id1].name);
	//	c.logEvent(c.contacts[id1],e)
	//	c.logEvent(c.contacts[sender],e)
	// } // We need to be able to logEvent to the proposed contact here too.
}

// Finds and parses all the pond-introduce-panda URLs in a message body.
// Returns a list of ProposedContacts from which to create add contact buttons.
func (c *client) parsePandaURLsText(sender uint64, body string) []ProposedContact {
	var l []ProposedContact
	re := regexp.MustCompile("(pond-introduce-panda)://([^/]+)/([^/]+)/([0-9A-Fa-f]{64})/")
	ms := re.FindAllStringSubmatch(body, -1) // -1 means find all
	const (
		urlparse_protocol            = 1
		urlparse_name                = 2
		urlparse_sharedSecret        = 3
		urlparse_theirIdentityPublic = 4
	)
	for _, m := range ms {
		if !panda.IsAcceptableSecretString(m[urlparse_sharedSecret]) {
			c.log.Printf("Unacceptably weak secret '%s' for %s.",
				m[urlparse_sharedSecret], m[urlparse_name])
		}
		var pc ProposedContact
		pc.sharedSecret = m[urlparse_sharedSecret]
		if !hexDecodeSafe(pc.theirIdentityPublic[:], m[urlparse_theirIdentityPublic]) {
			c.log.Printf("Bad public identity %s, skipping.", m[urlparse_theirIdentityPublic])
			continue
		}
		n, err := url.QueryUnescape(m[urlparse_name])
		if err != nil {
			c.log.Printf("Badly escaped name %s, fix using rename.", m[urlparse_name])
		} else {
			pc.name = n
		}
		l = append(l, pc)
		// We allow contacts to be added even if they fail these checks because
		// maybe they're the legit contact and the existing one is bad.
		c.checkProposedContactName(sender, pc)
	}
	return l
}

func (c *client) parsePandaURLs(msg *InboxMessage) []ProposedContact {
	var body string
	// msg.message could be nil if we're in a half paired message situation
	if msg.message != nil {
		body = string(msg.message.Body)
	}
	return c.parsePandaURLsText(msg.from, body)
}

// Add a ProposedContact using PANDA once by building panda.SharedSecret and
// the basic contact struct to call beginPandaKeyExchange.
func (c *client) beginProposedPandaKeyExchange(pc ProposedContact) *Contact {
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
	// theirIdentityPublic set distinguishes contacts pending by introduction
	// copy(contact.theirIdentityPublic[:], pc.theirIdentityPublic[:])

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