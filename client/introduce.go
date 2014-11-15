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

func addIdSet(set *[]uint64,id uint64) {
	for _,s := range *set {
		if s == id { return }
	}
	*set = append(*set,id)
}

func removeIdSet(set *[]uint64,id uint64) {
	for i,s := range *set {
		if s == id { 
			*set = append((*set)[:i], (*set)[i+1:]...)
			return
		}
	}
}

func (c *client) introducePandaMessages_pair(cnt1,cnt2 *Contact,real bool) (string,string) {
	panda_secret := panda.NewSecretString(c.rand)[2:]
	s := func(cnt *Contact) (string) {
		return fmt.Sprintf("pond-introduce-panda://%s/%s/%x/\n",
			url.QueryEscape(cnt.name),panda_secret,
			cnt.theirIdentityPublic) // no EncodeToString?
	}
	if real {
		addIdSet(&cnt1.introducedTo,cnt2.id)
		addIdSet(&cnt2.introducedTo,cnt1.id)
	}
	return s(cnt2), s(cnt1)
}

func (c *client) introducePandaMessages(shown,hidden contactList, real bool) ([]string,[]string) { 
	n := len(shown) + len(hidden)
	var urls []string = make([]string,n)
	cnts := append(shown,hidden...)
	for i := 0; i < len(shown); i++ {
		for j := i+1; j < n; j++ {
			ui,uj := c.introducePandaMessages_pair(cnts[i],cnts[j],real)
			urls[i] += ui 
			urls[j] += uj 
		}
	}
	return urls[0:len(shown)], urls[len(shown):]
}

func (c *client) introducePandaMessages_onemany(cnts contactList, real bool) ([]string) {
	urls1,urls2 := c.introducePandaMessages(contactList{cnts[0]},cnts[1:],real)
	return append(urls1,urls2...)
}

/*
func (c *client) introducePandaMessages_onemany(cnts contactList) ([]string) {
	var urls []string = make([]string,len(cnts))
	cnt1 := cnts[0]
	for i, cnt2 := range cnts[1:] {
		// if i==0 { continue }
		u1,u2 := c.introducePandaMessages_pair(cnt1,cnt2)
		urls[0] += u1 
		urls[i] = u2
	}
	return urls
}
*/

func (c *client) introducePandaMessages_group(cnts contactList, real bool) ([]string) {
	urls,_ := c.introducePandaMessages(cnts,nil,real)
	return urls
}

/*
func (c *client) introducePandaMessages_group(cnts contactList) ([]string) { 
	n := len(cnts)
	var urls []string = make([]string,len(cnts))
	// for i := 0; i < n; i++ { urls[i] = "" }
	for i := 0; i < n; i++ {
		for j := i+1; j < n; j++ {
			ui,uj := c.introducePandaMessages_pair(cnts[i],cnts[j])
			urls[i] += ui 
			urls[j] += uj 
		}
	}
	return urls
}
*/



type ProposedContact struct {
	sharedSecret string
	theirIdentityPublic [32]byte
	name string
	id uint64  // zero if new or failed
}

func (c *client) fixProposedContactName(pc ProposedContact,sender uint64) {
	// We should consider using JaroWinkler or Levenshtein from 
	// "github.com/antzucaro/matchr" here :
	//   https://godoc.org/github.com/antzucaro/matchr#JaroWinkler
	// Or maybe a fast fuzzy spelling suggestion algorithm 
	//   https://github.com/sajari/fuzzy
	// for _, contact := range c.contacts { }
	// At least we now alphabatize the contacts listing however.
	var s string
	_,ok := c.contactByName(pc.name)
	if !ok { return }
	for {
		var buf [2]byte
		c.randBytes(buf[:])
		s = fmt.Sprintf("/%s",buf)
		_,ok := c.contactByName(pc.name + s)
		if !ok { break }
	}
	c.log.Printf("Another contact is already named %s, appending %s.  Rename them, but make sure nothing nefarious happened.",
		pc.name,s); 
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
// We allow contacts to be added even if they fail most checks here because
// maybe they're the legit contact and the existing one is bad.
func (c *client) parsePandaURLs(sender uint64,body string) ([]ProposedContact) {
	var l []ProposedContact
	re := regexp.MustCompile("(pond-introduce-panda)://([^/]+)/([^/]+)/([0-9A-Fa-f]{64})/")
	ms := re.FindAllStringSubmatch(body,-1)  // -1 means find all
	const (
		urlparse_protocol = 1
		urlparse_name = 2
		urlparse_sharedSecret = 3
		urlparse_theirIdentityPublic = 4
	)
	for _, m := range ms {
		if ! panda.IsAcceptableSecretString(m[urlparse_sharedSecret]) {
			c.log.Printf("Unacceptably weak secret '%s' for %s.",
				m[urlparse_sharedSecret],m[urlparse_name]); 
		}

		var pc ProposedContact
		pc.sharedSecret = m[urlparse_sharedSecret]

		if ! hexDecodeSafe(pc.theirIdentityPublic[:],m[urlparse_theirIdentityPublic]) {
			c.log.Printf("Bad public identity %s, skipping.",m[urlparse_theirIdentityPublic]); 
			continue
		}
		if contact,found := c.contactByIdentity(pc.theirIdentityPublic[:]); found {
			pc.id = contact.id
			if contact.introducedBy != sender {
				addIdSet(&contact.verifiedBy,sender)
			}
		}

		n, err := url.QueryUnescape(m[urlparse_name])
		if err != nil { 
			c.log.Printf("Badly escaped name %s, fix using rename.",m[urlparse_name]);
		} else {
			pc.name = n
		}
		c.fixProposedContactName(pc,sender)

		l = append(l,pc)
	}
	return l
}

// Add a ProposedContact using PANDA once by building panda.SharedSecret and
// the basic contact struct to call beginPandaKeyExchange.  
func (c *client) beginProposedPandaKeyExchange(pc ProposedContact,introducedBy uint64) *Contact {
	if len(pc.sharedSecret) == 0 || ! panda.IsAcceptableSecretString(pc.sharedSecret) {
		c.log.Printf("Unacceptably weak secret '%s'.",pc.sharedSecret);
		return nil
	}
	if pc.id != 0 {
		c.log.Printf("Attempted to add introduced contact %s, who is your existing contact %s, this is an internal error.\n", termPrefix,
			pc.name,c.contacts[pc.id].name)
		return nil
	}

	contact := &Contact{
		name:      pc.name,
		isPending: true,
		id:        c.randId(),
		theirIdentityPublic: pc.theirIdentityPublic,
		introducedBy: introducedBy,
	}
	// theirIdentityPublic is set only for contacts pending by introduction
//	if introducedBy != 0 {
//		contact.introducedBy = introducedBy
//		copy(contact.theirIdentityPublic[:], pc.theirIdentityPublic[:])
//	}

	stack := &panda.CardStack{
		NumDecks: 1,
	}
	secret := panda.SharedSecret{
		Secret: pc.sharedSecret,
		Cards:  *stack,
	}
	c.newKeyExchange(contact)
	c.beginPandaKeyExchange(contact,secret)
	return contact
}
