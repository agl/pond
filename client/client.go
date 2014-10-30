package main

// The Pond client consists of a number of goroutines:
//
// The initial goroutine handles GTK and sits in the GTK event loop most of the
// time. It reads requests to change the UI from UI.Actions() and writes UI
// events to UI.Events(). Since its sitting in a GTK mainloop, after writing to
// UI.Actions(), UI.Signal() must be called which wakes up the UI goroutine and
// triggers the processing of any pending requests.
//
// The "main" goroutine is started immediately and exclusively drives the UI.
// The reason that the "main" goroutine isn't the initial goroutine is that, on
// OS X, the system really likes the native UI calls to be made from the
// initial thread.
//
// The main goroutine drives the startup process, loads state from disk etc.
// During startup it interacts with the UI channels directly but once startup
// has completed it sits in nextEvent(). The UI goroutine is callback based
// because GTK is callback based, but the main goroutine has a synchronous
// model. The nextEvent() call reads from a number of differnet channels,
// including UI.Events() and either processes the event directly, returns the
// event to the calling function, or returns and indicates that it's a global
// event. Global events are basically clicks on the left-hand-side of the UI
// which stop the current UI flow and start a different one.
//
// There are two utility goroutines with which the main goroutine communicates:
//
// The state writing goroutine is passed the serialised state for writing to
// the disk every time c.save() is called. It avoids having disk or TPM latency
// hang the main goroutine.
//
// The network goroutine handles sending and receiving messages. It shares a
// locked queue with the main goroutine in the form of client.queue. Once
// something has been added to the queue, the network goroutine owns it. This
// is complex when it comes to handling revocations because that involves
// resigning messages that have already been queued and thus part of the
// handling has to happen on the network goroutine.
//
// Lastly there are two types of O(n) goroutines: detachment and PANDA
// goroutines.
//
// Detachment goroutines handle the encryption/decryption and upload/download
// of detactments. They feed their results back into nextEvent().
//
// PANDA goroutines handle shared-secret key exchanges. They spend most of
// their time sleeping, waiting to poll the MeetingPlace. In tests, the mock
// MeetingPlace can be gracefully shutdown but, in normal operation, these
// goroutines are just killed. Their state is preserved because it's serialised
// whenever they write a log message.
//
//
// There are two flags that affect operation: dev and testing. Development mode
// is triggered by an environment variable: POND=dev. It causes a number of
// changes, including: servers are not contacted over Tor, fetches happen once
// every 5 seconds and the default server is on localhost.
//
// In addition to dev mode, there's testing mode. (Testing mode implies dev.)
// Testing mode is used by the unittests and generally changes things so that
// the tests can fully synchonise and avoid non-determinism.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"github.com/agl/pond/bbssig"
	"github.com/agl/pond/client/disk"
	"github.com/agl/pond/client/ratchet"
	"github.com/agl/pond/panda"
	pond "github.com/agl/pond/protos"
)

const (
	// messageLifetime is the default amount of time for which we'll keep a
	// message. (Counting from the time that it was received.)
	messageLifetime = 7 * 24 * time.Hour
	// messagePreIndicationLifetime is the amount of time that a message
	// remains before the background color changes to indicate that it will
	// be deleted soon.
	messagePreIndicationLifetime = 6 * 24 * time.Hour
	// messageGraceTime is the amount of time that we'll leave a message
	// before deletion after it has been marked as not-retained, or after
	// startup.
	messageGraceTime = 5 * time.Minute
	// The current protocol version implemented by this code.
	protoVersion = 1
)

const (
	shortTimeFormat = "Jan _2 15:04"
	logTimeFormat   = "Jan _2 15:04:05"
	keyExchangePEM  = "POND KEY EXCHANGE"
)

// client is the main structure containing most of the client's state.
type client struct {
	// testing is true in unittests and disables some assertions that are
	// needed in the real world, but which make testing difficult.
	testing bool
	// dev is true if POND=dev is in the environment. Unittests also set this.
	dev bool
	// autoFetch controls whether the network goroutine performs periodic
	// transactions or waits for outside prompting.
	autoFetch bool
	// newMeetingPlace is a function that returns a PANDA MeetingPlace. In
	// tests this can be overridden to return a testing meeting place.
	newMeetingPlace func() panda.MeetingPlace

	ui UI
	// stateFilename is the filename of the file on disk in which we
	// load/save our state.
	stateFilename string
	// stateLock protects the state against concurrent access by another
	// program.
	stateLock *disk.Lock
	// torAddress contains a string like "127.0.0.1:9050", which specifies
	// the address of the local Tor SOCKS proxy.
	torAddress string

	// server is the URL of the user's home server.
	server string
	// identity is a curve25519 private value that's used to authenticate
	// the client to its home server.
	identity, identityPublic [32]byte
	// groupPriv is the group private key for the user's delivery group.
	groupPriv *bbssig.PrivateKey
	// prevGroupPrivs contains previous group private keys that have been
	// revoked. This allows us to process messages that were inflight at
	// the time of the revocation.
	prevGroupPrivs []previousGroupPrivateKey
	// generation is the generation number of the group private key and is
	// incremented when a member of the group is revoked.
	generation uint32
	// priv is an Ed25519 private key.
	priv [64]byte
	// pub is the public key corresponding to |priv|.
	pub  [32]byte
	rand io.Reader
	// lastErasureStorageTime is the time at which we last rotated the
	// erasure storage value.
	lastErasureStorageTime time.Time
	// writerChan is a channel that the disk goroutine reads from to
	// receive updated, serialised states.
	writerChan chan disk.NewState
	// writerDone is a channel that is closed by the disk goroutine when it
	// has finished all pending updates.
	writerDone chan struct{}
	// fetchNowChan is the channel that the network goroutine reads from
	// that triggers an immediate network transaction. Mostly intended for
	// testing.
	fetchNowChan chan chan bool

	log *Log

	// outbox contains all outgoing messages.
	outbox   []*queuedMessage
	drafts   map[uint64]*Draft
	contacts map[uint64]*Contact
	inbox    []*InboxMessage

	// queue is a queue of messages for transmission that's shared with the
	// network goroutine and protected by queueMutex.
	queue      []*queuedMessage
	queueMutex sync.Mutex
	// newMessageChan receives messages that have been read from the home
	// server by the network goroutine.
	newMessageChan chan NewMessage
	// messageSentChan receives the ids of messages that have been sent by
	// the network goroutine.
	messageSentChan chan messageSendResult
	// backgroundChan is used for signals from background processes - e.g.
	// detachment uploads.
	backgroundChan chan interface{}
	// pandaChan receives messages from goroutines in runPANDA about
	// changes to PANDA key exchange state.
	pandaChan chan pandaUpdate
	// pandaWaitGroup is incremented for each running PANDA goroutine.
	pandaWaitGroup sync.WaitGroup
	// signingRequestChan receives requests to sign messages for delivery,
	// just before they are sent to the destination server.
	signingRequestChan chan signingRequest

	// usedIds records ID numbers that have been assigned in the current
	// state file.
	usedIds map[uint64]bool

	// timerChan fires every two minutes so that messages can be erased.
	timerChan <-chan time.Time
	// nowFunc is a function that, if not nil, will be used by the GUI to
	// get the current time. This is used in testing.
	nowFunc func() time.Time

	// simulateOldClient causes the client to act like a pre-ratchet client
	// for testing purposes.
	simulateOldClient bool

	// disableV2Ratchet causes the client to advertise and process V1
	// axolotl ratchet support.
	disableV2Ratchet bool

	// command to run upon receiving messages
	receiveHookCommand string
}

// UI abstracts behaviour that is specific to a given interface (GUI or CLI).
// Generic code can call these functions to perform interface-specific
// behaviour.
type UI interface {
	initUI()
	// loadingUI shows a basic "loading" prompt while the state file is read.
	loadingUI()
	// torPromptUI prompts the user to start Tor.
	torPromptUI() error
	// sleepUI waits the given amount of time or never returns if the user
	// closes the UI.
	sleepUI(d time.Duration) error
	// errorUI shows an error and returns.
	errorUI(msg string, fatal bool)
	// ShutdownAndSuspend quits the program - possibly waiting for the user
	// to close the window in the case of a GUI so any error message can be
	// read first.
	ShutdownAndSuspend() error
	createPassphraseUI() (string, error)
	createErasureStorage(pw string, stateFile *disk.StateFile) error
	// createAccountUI allows the user to either create a new account or to
	// import from a entombed statefile. It returns whether an import
	// occured and an error.
	createAccountUI(stateFile *disk.StateFile, pw string) (bool, error)
	keyPromptUI(stateFile *disk.StateFile) error
	processFetch(msg *InboxMessage)
	processServerAnnounce(announce *InboxMessage)
	processAcknowledgement(ackedMsg *queuedMessage)
	// processRevocationOfUs is called when a revocation is received that
	// revokes our group key for a contact.
	processRevocationOfUs(by *Contact)
	// processRevocation is called when we have finished processing a
	// revocation. This includes revocations of others and of this
	// ourselves. In the latter case, this is called after
	// processRevocationOfUs.
	processRevocation(by *Contact)
	// processMessageSent is called when an outbox message has been
	// delivered to the destination server.
	processMessageDelivered(msg *queuedMessage)
	// processPANDAUpdateUI is called on each PANDA update to update the
	// UI and unseal pending messages.
	processPANDAUpdateUI(update pandaUpdate)
	// removeInboxMessageUI removes a message from the inbox UI.
	removeInboxMessageUI(msg *InboxMessage)
	// removeOutboxMessageUI removes a message from the outbox UI.
	removeOutboxMessageUI(msg *queuedMessage)
	// addRevocationMessageUI notifies the UI that a new revocation message
	// has been created.
	addRevocationMessageUI(msg *queuedMessage)
	// removeContactUI removes a contact from the UI.
	removeContactUI(contact *Contact)
	// logEventUI is called when an exceptional event has been logged for
	// the given contact.
	logEventUI(contact *Contact, event Event)
	// mainUI starts the main interface.
	mainUI()
}

type messageSendResult struct {
	// If the id is zero then a message wasn't actually sent - this is just
	// the transact goroutine poking the UI because the queue has been
	// updated.
	id uint64
	// revocation optionally contains a revocation update that resulted
	// from attempting to send a message.
	revocation *pond.SignedRevocation
	// extraRevocations optionally contains revocations further to
	// |revocation|. This is only non-empty if |revocation| is non-nil.
	extraRevocations []*pond.SignedRevocation
}

// signingRequest is a structure that is sent from the network thread to the
// main thread to request that a message be signed with a group signature for
// delivery.
type signingRequest struct {
	msg        *queuedMessage
	resultChan chan *pond.Request
}

// pendingDecryption represents a detachment decryption/download operation
// that's in progress. These are not saved to disk.
type pendingDecryption struct {
	// index is used by the UI code and indexes the list of detachments in
	// a message.
	index int
	// cancel is a thunk that causes the task to be canceled at some point
	// in the future.
	cancel func()
}

// cliId represents a short, unique ID that is assigned by the command-line
// interface so that users can select an object by typing a short sequence of
// letters and digits. The value is 15 bits long and represented as a string in
// z-base-32.
type cliId uint

const invalidCliId cliId = 0

// See http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
const zBase32Chars = "ybndrfg8ejkmcpqxot1uwisza345h769"

func (id cliId) String() string {
	var chars [3]byte

	for i := range chars {
		chars[i] = zBase32Chars[id&31]
		id >>= 5
	}

	return string(chars[:])
}

func cliIdFromString(s string) (id cliId, ok bool) {
	if len(s) != 3 {
		return
	}

	var shift uint

NextChar:
	for _, r := range s {
		for i, r2 := range zBase32Chars {
			if r == r2 {
				id |= cliId(i) << shift
				shift += 5
				continue NextChar
			}
		}

		return
	}

	ok = true
	return
}

// InboxMessage represents a message in the client's inbox. (Acks also appear
// as InboxMessages, but their message.Body is empty.)
type InboxMessage struct {
	id           uint64
	read         bool
	receivedTime time.Time
	from         uint64
	// sealed contained the encrypted message if the contact who sent this
	// message is still pending.
	sealed []byte
	acked  bool
	// message may be nil if the contact who sent this is pending. In this
	// case, sealed with contain the encrypted message.
	message *pond.Message
	// cliId is a number, assigned by the command-line interface, to
	// identity this message for the duration of the session. It's not
	// saved to disk.
	cliId cliId
	// retained is true if the user has chosen to retain this message -
	// i.e. to opt it out of the usual, time-based, auto-deletion.
	retained bool
	// exposureTime contains the time when the message was last "exposed".
	// This is used to allow a small period of time for the user to mark a
	// message as retained (messageGraceTime). For example, if a message is
	// loaded at startup and has expired then it's a candidate for
	// deletion, but the exposureTime will be the startup time, which
	// ensures that we leave it a few minutes before deletion. Setting
	// retained to false also resets the exposureTime.
	exposureTime time.Time

	decryptions map[uint64]*pendingDecryption
}

func (msg *InboxMessage) Strings() (sentTime, eraseTime, body string) {
	isPending := msg.message == nil
	if isPending {
		body = "(cannot display message as key exchange is still pending)"
		sentTime = "(unknown)"
	} else {
		sentTime = time.Unix(*msg.message.Time, 0).Format(time.RFC1123)
		body = "(cannot display message as encoding is not supported)"
		if msg.message.BodyEncoding != nil {
			switch *msg.message.BodyEncoding {
			case pond.Message_RAW:
				body = string(msg.message.Body)
			}
		}
	}
	eraseTime = msg.receivedTime.Add(messageLifetime).Format(time.RFC1123)
	return
}

// NewMessage is sent from the network goroutine to the client goroutine and
// contains messages fetched from the home server.
type NewMessage struct {
	fetched  *pond.Fetched
	announce *pond.ServerAnnounce
	ack      chan bool
}

// Contact represents a contact to which we can send messages.
type Contact struct {
	// id is only locally valid.
	id uint64
	// name is the friendly name that the user chose for this contact. It
	// is unique for all contacts.
	name string
	// isPending is true if we haven't received a key exchange message from
	// this contact.
	isPending bool
	// kxsBytes is the serialised key exchange message that we generated
	// for this contact. (Only valid if |isPending| is true.)
	kxsBytes []byte
	// groupKey is the group member key that we gave to this contact.
	// myGroupKey is the one that they gave to us.
	groupKey, myGroupKey *bbssig.MemberKey
	// previousTags contains bbssig tags that were previously used by this
	// contact. The tag of a contact changes when a recovation is
	// processed, but old messages may still be queued.
	previousTags []previousTag
	// generation is the current group generation number that we know for
	// this contact.
	generation uint32
	// theirServer is the URL of the contact's home server.
	theirServer string
	// theirPub is their Ed25519 public key.
	theirPub [32]byte
	// theirIdentityPublic is the public identity that their home server
	// knows them by.
	theirIdentityPublic [32]byte
	// supportedVersion contains the greatest protocol version number that
	// we have observed from this contact.
	supportedVersion int32
	// revoked is true if this contact has been revoked.
	revoked bool
	// revokedUs is true if this contact has recoved us.
	revokedUs bool
	// pandaKeyExchange contains the serialised PANDA state if a key
	// exchange is ongoing.
	pandaKeyExchange []byte
	// pandaShutdownChan is a channel that can be closed to trigger the
	// shutdown of an individual PANDA exchange.
	pandaShutdownChan chan struct{}
	// pandaResult contains an error message in the event that a PANDA key
	// exchange failed.
	pandaResult string
	// events contains a log of important events relating to this contact.
	events []Event

	// Members for the old ratchet.
	lastDHPrivate        [32]byte
	currentDHPrivate     [32]byte
	theirLastDHPublic    [32]byte
	theirCurrentDHPublic [32]byte

	// New ratchet support.
	ratchet *ratchet.Ratchet

	cliId cliId
}

// Event represents a log entry. This does not apply to the global log, which
// is quite chatty, but rather to significant events related to a given
// contact. These events are surfaced in the UI and recorded in the statefile.
type Event struct {
	t   time.Time
	msg string
}

// previousTagLifetime contains the amount of time that we'll store a previous
// tag (or previous group private key) for.
const previousTagLifetime = 14 * 24 * time.Hour

// previousTag represents a group signature tag that was previously assigned to
// a contact. In the event of a revocation, all the tags change but we need to
// know the previous tags for a certain amount of time because messages may
// have been created before the contact saw the revocation update.
type previousTag struct {
	tag []byte
	// expired contains the time at which this tag was expired - i.e. the
	// timestamp when the revocation occured.
	expired time.Time
}

// previousGroupPrivateKey represents a group private key that has been
// revoked. These are retained for the same reason as previous tags.
type previousGroupPrivateKey struct {
	priv *bbssig.PrivateKey
	// expired contains the time at which this tag was expired - i.e. the
	// timestamp when the revocation occured.
	expired time.Time
}

// pendingDetachment represents a detachment conversion/upload operation that's
// in progress. These are not saved to disk.
type pendingDetachment struct {
	size   int64
	path   string
	cancel func()
}

type Draft struct {
	id          uint64
	created     time.Time
	to          uint64
	body        string
	inReplyTo   uint64
	attachments []*pond.Message_Attachment
	detachments []*pond.Message_Detachment
	// cliId is a number, assigned by the command-line interface, to
	// identity this message for the duration of the session. It's not
	// saved to disk.
	cliId cliId

	// pendingDetachments is only used by the GTK UI.
	pendingDetachments map[uint64]*pendingDetachment
}

// prettyNumber formats n in base 10 and puts commas between groups of
// thousands.
func prettyNumber(n uint64) string {
	s := strconv.FormatUint(n, 10)
	ret := make([]rune, 0, len(s)*2)

	phase := len(s) % 3
	for i, r := range s {
		if phase == 0 && i > 0 {
			ret = append(ret, ',')
		}
		ret = append(ret, r)
		phase--
		if phase < 0 {
			phase += 3
		}
	}

	return string(ret)
}

// usageString returns a description of the amount of space taken up by a body
// with the given contents and a bool indicating overflow.
func (draft *Draft) usageString() (string, bool) {
	var replyToId *uint64
	if draft.inReplyTo != 0 {
		replyToId = proto.Uint64(1)
	}
	var dhPub [32]byte

	msg := &pond.Message{
		Id:               proto.Uint64(0),
		Time:             proto.Int64(1 << 62),
		Body:             []byte(draft.body),
		BodyEncoding:     pond.Message_RAW.Enum(),
		InReplyTo:        replyToId,
		MyNextDh:         dhPub[:],
		Files:            draft.attachments,
		DetachedFiles:    draft.detachments,
		SupportedVersion: proto.Int32(protoVersion),
	}

	serialized, err := proto.Marshal(msg)
	if err != nil {
		panic("error while serialising candidate Message: " + err.Error())
	}

	s := fmt.Sprintf("%s of %s bytes", prettyNumber(uint64(len(serialized))), prettyNumber(pond.MaxSerializedMessage))
	return s, len(serialized) > pond.MaxSerializedMessage
}

type queuedMessage struct {
	request    *pond.Request
	id         uint64
	to         uint64
	server     string
	created    time.Time
	sent       time.Time
	acked      time.Time
	revocation bool
	message    *pond.Message

	// sending is true if the transact goroutine is currently sending this
	// message. This is protected by the queueMutex.
	sending bool

	// cliId is a number, assigned by the command-line interface, to
	// identity this message for the duration of the session. It's not
	// saved to disk.
	cliId cliId
}

func (qm *queuedMessage) indicator(contact *Contact) Indicator {
	switch {
	case !qm.acked.IsZero():
		return indicatorGreen
	case !qm.sent.IsZero():
		if qm.revocation {
			// Revocations are never acked so they are green as
			// soon as they are sent.
			return indicatorGreen
		}
		return indicatorYellow
	case contact != nil && contact.revokedUs:
		return indicatorBlack
	}
	return indicatorRed
}

// outboxToDraft converts an outbox message back to a Draft. This is used when
// the user aborts the sending of a message.
func (c *client) outboxToDraft(msg *queuedMessage) *Draft {
	draft := &Draft{
		id:          msg.id,
		created:     msg.created,
		to:          msg.to,
		body:        string(msg.message.Body),
		attachments: msg.message.Files,
		detachments: msg.message.DetachedFiles,
	}

	if irt := msg.message.GetInReplyTo(); irt != 0 {
		// The inReplyTo value of a draft references *our* id for the
		// inbox message. But the InReplyTo field of a pond.Message
		// references's the contact's id for the message. So we need to
		// enumerate the messages in the inbox from that contact and
		// find the one with the matching id.
		for _, inboxMsg := range c.inbox {
			if inboxMsg.from == msg.to && inboxMsg.message != nil && inboxMsg.message.GetId() == irt {
				draft.inReplyTo = inboxMsg.id
				break
			}
		}
	}

	return draft
}

func (c *client) ContactName(id uint64) string {
	if id == 0 {
		return "Home Server"
	}
	return c.contacts[id].name
}

// detectTor sets c.torAddress, either from the POND_TOR_ADDRESS environment
// variable if it is set or by attempting to connect to port 9050 and 9150 on
// the local host and assuming that Tor is running on the first port that it
// finds to be open.
func (c *client) detectTor() bool {
	if addr := os.Getenv("POND_TOR_ADDRESS"); len(addr) != 0 {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			c.log.Printf("Ignoring POND_TOR_ADDRESS because of parse error: %s", err)
		} else {
			c.torAddress = addr
			c.log.Printf("Using POND_TOR_ADDRESS=%s", addr)
			return true
		}
	}

	ports := []int{9050, 9150}
	for _, port := range ports {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			continue
		}
		c.torAddress = addr
		conn.Close()
		return true
	}

	return false
}

var knownServers = []struct {
	nickname    string
	description string
	uri         string
}{
	{"wau", "Wau Holland Foundation", "pondserver://25WHHEVD3565FGIOXJZWV7LGQFR4BTO3HF3FWHEW7PCYPFMFPVOQ@vx652n4utsodj5c6.onion"},
	{"hoi", "Hoi Polloi (https://hoi-polloi.org)", "pondserver://4V6Q5M2AFLBW6UIYL2B5LMKDHEBA6HRHR6UIUU3VDQFNI3BHZAEQ@oum7argqrnlzpcro.onion"},
}

func (c *client) enqueue(m *queuedMessage) {
	c.queueMutex.Lock()
	defer c.queueMutex.Unlock()

	c.queue = append(c.queue, m)
}

func maybeTruncate(s string) string {
	if runes := []rune(s); len(runes) > 30 {
		runes = runes[:30]
		runes = append(runes, 0x2026 /* ellipsis */)
		return string(runes)
	}
	return s
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "(not yet)"
	}
	return t.Format(time.RFC1123)
}

var errInterrupted = errors.New("cli: interrupt signal")

func (c *client) loadUI() error {
	c.ui.initUI()

	c.torAddress = "127.0.0.1:9050" // default for dev mode.
	if !c.dev && !c.detectTor() {
		if err := c.ui.torPromptUI(); err != nil {
			return err
		}
	}

	c.receiveHookCommand = os.Getenv("POND_HOOK_RECEIVE")

	c.ui.loadingUI()

	stateFile := &disk.StateFile{
		Path: c.stateFilename,
		Rand: c.rand,
		Log: func(format string, args ...interface{}) {
			c.log.Printf(format, args...)
		},
	}

	var newAccount, imported bool
	var err error
	if c.stateLock, err = stateFile.Lock(false /* don't create */); err == nil && c.stateLock == nil {
		c.ui.errorUI("State file locked by another process. Waiting for lock.", false)
		c.log.Errorf("Waiting for locked state file")

		for {
			if c.stateLock, err = stateFile.Lock(false /* don't create */); c.stateLock != nil {
				break
			}
			if err := c.ui.sleepUI(1 * time.Second); err != nil {
				return err
			}
		}
	} else if err == nil {
	} else if os.IsNotExist(err) {
		newAccount = true
	} else {
		c.ui.errorUI(err.Error(), true)
		if err := c.ui.ShutdownAndSuspend(); err != nil {
			return err
		}
	}

	if newAccount {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		copy(c.priv[:], priv[:])
		copy(c.pub[:], pub[:])

		if c.disableV2Ratchet {
			c.randBytes(c.identity[:])
		} else {
			extra25519.PrivateKeyToCurve25519(&c.identity, priv)
		}
		curve25519.ScalarBaseMult(&c.identityPublic, &c.identity)

		c.groupPriv, err = bbssig.GenerateGroup(rand.Reader)
		if err != nil {
			panic(err)
		}
		pw, err := c.ui.createPassphraseUI()
		if err != nil {
			return err
		}
		c.ui.createErasureStorage(pw, stateFile)
		imported, err = c.ui.createAccountUI(stateFile, pw)
		if err != nil {
			return err
		}
	} else {
		// First try with zero key.
		err := c.loadState(stateFile, "")
		for err == disk.BadPasswordError {
			// That didn't work, try prompting for a key.
			err = c.ui.keyPromptUI(stateFile)
		}
		if err == errInterrupted {
			return err
		}
		if err != nil {
			// Fatal error loading state. Abort.
			c.ui.errorUI(err.Error(), true)
			if err := c.ui.ShutdownAndSuspend(); err != nil {
				return err
			}
		}
	}

	if newAccount && !imported {
		c.stateLock, err = stateFile.Lock(true /* create */)
		if err != nil {
			err = errors.New("Failed to create state file: " + err.Error())
		} else if c.stateLock == nil {
			err = errors.New("Failed to obtain lock on created state file")
		}
		if err != nil {
			c.ui.errorUI(err.Error(), true)
			if err := c.ui.ShutdownAndSuspend(); err != nil {
				return err
			}
		}
		c.lastErasureStorageTime = time.Now()
	}

	c.writerChan = make(chan disk.NewState)
	c.writerDone = make(chan struct{})
	c.fetchNowChan = make(chan chan bool, 1)

	// Start disk and network workers.
	go stateFile.StartWriter(c.writerChan, c.writerDone)
	go c.transact()
	if newAccount {
		c.save()
	}

	// Start any pending key exchanges.
	for _, contact := range c.contacts {
		if len(contact.pandaKeyExchange) == 0 {
			continue
		}
		c.pandaWaitGroup.Add(1)
		contact.pandaShutdownChan = make(chan struct{})
		go c.runPANDA(contact.pandaKeyExchange, contact.id, contact.name, contact.pandaShutdownChan)
	}

	c.ui.mainUI()

	return nil
}

func (contact *Contact) subline() string {
	switch {
	case contact.revokedUs:
		return "has revoked"
	case contact.isPending:
		return "pending"
	case len(contact.pandaResult) > 0:
		return "failed"
	case !contact.isPending && contact.ratchet == nil:
		return "old ratchet"
	}
	return ""
}

func (contact *Contact) indicator() Indicator {
	switch {
	case contact.revokedUs:
		return indicatorBlack
	case contact.isPending:
		return indicatorYellow
	}
	return indicatorNone
}

func (contact *Contact) processKeyExchange(kxsBytes []byte, testing, simulateOldClient, disableV2Ratchet bool) error {
	var kxs pond.SignedKeyExchange
	if err := proto.Unmarshal(kxsBytes, &kxs); err != nil {
		return err
	}

	var sig [64]byte
	if len(kxs.Signature) != len(sig) {
		return errors.New("invalid signature length")
	}
	copy(sig[:], kxs.Signature)

	var kx pond.KeyExchange
	if err := proto.Unmarshal(kxs.Signed, &kx); err != nil {
		return err
	}

	if len(kx.PublicKey) != len(contact.theirPub) {
		return errors.New("invalid public key")
	}
	copy(contact.theirPub[:], kx.PublicKey)

	if !ed25519.Verify(&contact.theirPub, kxs.Signed, &sig) {
		return errors.New("invalid signature")
	}

	contact.theirServer = *kx.Server
	if _, _, err := parseServer(contact.theirServer, testing); err != nil {
		return err
	}

	group, ok := new(bbssig.Group).Unmarshal(kx.Group)
	if !ok {
		return errors.New("invalid group")
	}
	if contact.myGroupKey, ok = new(bbssig.MemberKey).Unmarshal(group, kx.GroupKey); !ok {
		return errors.New("invalid group key")
	}

	if len(kx.IdentityPublic) != len(contact.theirIdentityPublic) {
		return errors.New("invalid public identity")
	}
	copy(contact.theirIdentityPublic[:], kx.IdentityPublic)

	if simulateOldClient {
		kx.Dh1 = nil
	}

	if len(kx.Dh1) == 0 {
		// They are using an old-style ratchet. We have to extract the
		// private value from the Ratchet in order to use it with the
		// old code.
		contact.lastDHPrivate = contact.ratchet.GetKXPrivateForTransition()
		if len(kx.Dh) != len(contact.theirCurrentDHPublic) {
			return errors.New("invalid public DH value")
		}
		copy(contact.theirCurrentDHPublic[:], kx.Dh)
		contact.ratchet = nil
	} else {
		// If the identity and ed25519 public keys are the same (modulo
		// isomorphism) then the contact is using the v2 ratchet.
		var ed25519Public, curve25519Public [32]byte
		copy(ed25519Public[:], kx.PublicKey)
		extra25519.PublicKeyToCurve25519(&curve25519Public, &ed25519Public)
		v2 := !disableV2Ratchet && bytes.Equal(curve25519Public[:], kx.IdentityPublic[:])
		if err := contact.ratchet.CompleteKeyExchange(&kx, v2); err != nil {
			return err
		}
	}

	contact.generation = *kx.Generation

	return nil
}

// logEvent records an exceptional event relating to the given contact.
func (c *client) logEvent(contact *Contact, msg string) {
	event := Event{
		t:   time.Now(),
		msg: msg,
	}
	contact.events = append(contact.events, event)
	c.log.Errorf("While processing message from %s: %s", contact.name, msg)
	c.ui.logEventUI(contact, event)
}

func (c *client) randBytes(buf []byte) {
	if _, err := io.ReadFull(c.rand, buf); err != nil {
		panic(err)
	}
}

func (c *client) randId() uint64 {
	var idBytes [8]byte
	for {
		c.randBytes(idBytes[:])
		n := binary.LittleEndian.Uint64(idBytes[:])
		if n == 0 {
			continue
		}
		if c.usedIds[n] {
			continue
		}
		c.usedIds[n] = true
		return n
	}
	panic("unreachable")
}

// Now is a wrapper around time.Now() that allows unittests to override the
// current time.
func (c *client) Now() time.Time {
	if c.nowFunc == nil {
		return time.Now()
	}
	return c.nowFunc()
}

// registerId records that an ID number has been used, typically because we are
// loading a state file.
func (c *client) registerId(id uint64) {
	if c.usedIds[id] {
		panic("duplicate ID registered")
	}
	c.usedIds[id] = true
}

func (c *client) newRatchet(contact *Contact) *ratchet.Ratchet {
	r := ratchet.New(c.rand)
	r.MyIdentityPrivate = &c.identity
	r.MySigningPublic = &c.pub
	r.TheirIdentityPublic = &contact.theirIdentityPublic
	r.TheirSigningPublic = &contact.theirPub
	return r
}

func (c *client) newKeyExchange(contact *Contact) {
	var err error
	if contact.groupKey, err = c.groupPriv.NewMember(c.rand); err != nil {
		panic(err)
	}
	contact.ratchet = c.newRatchet(contact)

	kx := &pond.KeyExchange{
		PublicKey:      c.pub[:],
		IdentityPublic: c.identityPublic[:],
		Server:         proto.String(c.server),
		Group:          contact.groupKey.Group.Marshal(),
		GroupKey:       contact.groupKey.Marshal(),
		Generation:     proto.Uint32(c.generation),
	}
	contact.ratchet.FillKeyExchange(kx)
	if c.simulateOldClient {
		kx.Dh1 = nil
	}

	kxBytes, err := proto.Marshal(kx)
	if err != nil {
		panic(err)
	}

	sig := ed25519.Sign(&c.priv, kxBytes)

	kxs := &pond.SignedKeyExchange{
		Signed:    kxBytes,
		Signature: sig[:],
	}

	if contact.kxsBytes, err = proto.Marshal(kxs); err != nil {
		panic(err)
	}
}

func (c *client) deleteInboxMsg(id uint64) {
	newInbox := make([]*InboxMessage, 0, len(c.inbox))
	for _, inboxMsg := range c.inbox {
		if inboxMsg.id == id {
			continue
		}
		newInbox = append(newInbox, inboxMsg)
	}
	c.inbox = newInbox
}

// dropSealedAndAckMessagesFrom removes all sealed or pure-ack messages from
// the given contact, from the inbox.
func (c *client) dropSealedAndAckMessagesFrom(contact *Contact) {
	newInbox := make([]*InboxMessage, 0, len(c.inbox))
	for _, inboxMsg := range c.inbox {
		if inboxMsg.from == contact.id &&
			(len(inboxMsg.sealed) > 0 ||
				(inboxMsg.message != nil && len(inboxMsg.message.Body) == 0)) {
			continue
		}
		newInbox = append(newInbox, inboxMsg)
	}
	c.inbox = newInbox
}

func (c *client) deleteOutboxMsg(id uint64) {
	newOutbox := make([]*queuedMessage, 0, len(c.outbox))
	for _, outboxMsg := range c.outbox {
		if outboxMsg.id == id {
			continue
		}
		newOutbox = append(newOutbox, outboxMsg)
	}
	c.outbox = newOutbox
}

func (c *client) indexOfQueuedMessage(msg *queuedMessage) (index int) {
	// c.queueMutex must be held before calling this function.

	for i, queuedMsg := range c.queue {
		if queuedMsg == msg {
			return i
		}
	}

	return -1
}

func (c *client) removeQueuedMessage(index int) {
	// c.queueMutex must be held before calling this function.

	var newQueue []*queuedMessage
	for i, queuedMsg := range c.queue {
		if i != index {
			newQueue = append(newQueue, queuedMsg)
		}
	}
	c.queue = newQueue
}

func (c *client) moveContactsMessagesToEndOfQueue(id uint64) {
	// c.queueMutex must be held before calling this function.

	if len(c.queue) < 2 {
		// There are no other orders for queues of length zero or one.
		return
	}

	newQueue := make([]*queuedMessage, 0, len(c.queue))
	movedMessages := make([]*queuedMessage, 0, 2)

	for _, queuedMsg := range c.queue {
		if queuedMsg.to == id {
			movedMessages = append(movedMessages, queuedMsg)
		} else {
			newQueue = append(newQueue, queuedMsg)
		}
	}
	newQueue = append(newQueue, movedMessages...)
	c.queue = newQueue
}

func (c *client) deleteContact(contact *Contact) {
	var newInbox []*InboxMessage
	for _, msg := range c.inbox {
		if msg.from == contact.id {
			c.ui.removeInboxMessageUI(msg)
			continue
		}
		newInbox = append(newInbox, msg)
	}
	c.inbox = newInbox

	for _, draft := range c.drafts {
		if draft.to == contact.id {
			draft.to = 0
		}
	}

	c.queueMutex.Lock()
	var newQueue []*queuedMessage
	for _, msg := range c.queue {
		if msg.to == contact.id && !msg.revocation {
			continue
		}
		newQueue = append(newQueue, msg)
	}
	c.queue = newQueue
	c.queueMutex.Unlock()

	var newOutbox []*queuedMessage
	for _, msg := range c.outbox {
		if msg.to == contact.id && !msg.revocation {
			c.ui.removeOutboxMessageUI(msg)
			continue
		}
		newOutbox = append(newOutbox, msg)
	}
	c.outbox = newOutbox

	revocationMessage := c.revoke(contact)
	c.ui.addRevocationMessageUI(revocationMessage)

	if contact.pandaShutdownChan != nil {
		close(contact.pandaShutdownChan)
	}

	c.ui.removeContactUI(contact)
	delete(c.contacts, contact.id)
}

// indentForReply returns a copy of in where the beginning of each line is
// prefixed with "> ", as is typical for replies.
func indentForReply(i []byte) string {
	in := bufio.NewReader(bytes.NewBuffer(i))
	var out bytes.Buffer

	newLine := true
	for {
		line, isPrefix, err := in.ReadLine()
		if err != nil {
			break
		}

		if newLine {
			if len(line) > 0 {
				out.WriteString("> ")
			} else {
				out.WriteString(">")
			}
		}
		out.Write(line)
		newLine = !isPrefix
		if !isPrefix {
			out.WriteString("\n")
		}
	}

	return string(out.Bytes())
}

// RunPANDA runs in its own goroutine and runs a PANDA key exchange.
func (c *client) runPANDA(serialisedKeyExchange []byte, id uint64, name string, shutdown chan struct{}) {
	var result []byte
	defer c.pandaWaitGroup.Done()

	c.log.Printf("Starting PANDA key exchange with %s", name)

	kx, err := panda.UnmarshalKeyExchange(c.rand, c.newMeetingPlace(), serialisedKeyExchange)
	kx.Testing = c.testing
	kx.Log = func(format string, args ...interface{}) {
		serialised := kx.Marshal()
		c.pandaChan <- pandaUpdate{
			id:         id,
			serialised: serialised,
		}
		c.log.Printf("Key exchange with %s: %s", name, fmt.Sprintf(format, args...))
	}
	kx.ShutdownChan = shutdown

	if err == nil {
		result, err = kx.Run()
	}

	if err == panda.ShutdownErr {
		return
	}

	c.pandaChan <- pandaUpdate{
		id:     id,
		err:    err,
		result: result,
	}
}

// processPANDAUpdate runs on the main client goroutine and handles messages
// from a runPANDA goroutine.
func (c *client) processPANDAUpdate(update pandaUpdate) {
	contact, ok := c.contacts[update.id]
	if !ok {
		return
	}

	switch {
	case update.err != nil:
		contact.pandaResult = update.err.Error()
		contact.pandaKeyExchange = nil
		contact.pandaShutdownChan = nil
		c.log.Printf("Key exchange with %s failed: %s", contact.name, update.err)
	case update.serialised != nil:
		if bytes.Equal(contact.pandaKeyExchange, update.serialised) {
			return
		}
		contact.pandaKeyExchange = update.serialised
	case update.result != nil:
		contact.pandaKeyExchange = nil
		contact.pandaShutdownChan = nil

		if err := contact.processKeyExchange(update.result, c.dev, c.simulateOldClient, c.disableV2Ratchet); err != nil {
			contact.pandaResult = err.Error()
			update.err = err
			c.log.Printf("Key exchange with %s failed: %s", contact.name, err)
		} else {
			c.log.Printf("Key exchange with %s complete", contact.name)
			contact.isPending = false
		}
	}

	c.ui.processPANDAUpdateUI(update)
	c.save()
}

type pandaUpdate struct {
	id         uint64
	err        error
	result     []byte
	serialised []byte
}

func openAttachment(path string) (contents []byte, size int64, err error) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	fi, err := file.Stat()
	if err != nil {
		return
	}
	if fi.Size() < pond.MaxSerializedMessage-500 {
		contents, err = ioutil.ReadAll(file)
		size = -1
	} else {
		size = fi.Size()
	}
	return
}

// entomb encrypts and *destroys* the statefile. The encrypted statefile is
// written to tombFile (with tombPath). The function log will be called during
// the process to give status updates. It returns the random key of the
// encrypted statefile and whether the process was successful. If unsuccessful,
// the original statefile will not be destroyed.
func (c *client) entomb(tombPath string, tombFile *os.File, log func(string, ...interface{})) (keyHex *[32]byte, ok bool) {
	log("Emtombing statefile to %s\n", tombPath)
	log("Stopping network processing...\n")
	if c.fetchNowChan != nil {
		close(c.fetchNowChan)
	}
	log("Stopping active key exchanges...\n")
	for _, contact := range c.contacts {
		if contact.pandaShutdownChan != nil {
			close(contact.pandaShutdownChan)
		}
	}
	log("Serialising state...\n")
	stateBytes := c.marshal()

	var key [32]byte
	c.randBytes(key[:])
	var nonce [24]byte
	log("Encrypting...\n")
	encrypted := secretbox.Seal(nil, stateBytes, &nonce, &key)

	log("Writing...\n")
	if _, err := tombFile.Write(encrypted); err != nil {
		log("Error writing: %s\n", err)
		return nil, false
	}
	log("Syncing...\n")
	if err := tombFile.Sync(); err != nil {
		log("Error syncing: %s\n", err)
		return nil, false
	}
	if err := tombFile.Close(); err != nil {
		log("Error closing: %s\n", err)
		return nil, false
	}

	readBack, err := ioutil.ReadFile(tombPath)
	if err != nil {
		log("Error rereading: %s\n", err)
		return nil, false
	}
	if !bytes.Equal(readBack, encrypted) {
		log("Contents of tomb file incorrect\n")
		return nil, false
	}

	log("The ephemeral key is: %x\n", key)
	log("You must write the ephemeral key down now! Store it somewhat erasable!\n")

	log("Erasing statefile... ")
	c.writerChan <- disk.NewState{stateBytes, false, true /* destruct */}
	<-c.writerDone
	log("done\n")

	return &key, true
}

// importTombFile decrypts a file with the given path, using a hex-encoded key
// and loads the client state from the result.
func (c *client) importTombFile(stateFile *disk.StateFile, keyHex, path string) error {
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return err
	}

	var key [32]byte
	var nonce [24]byte
	if len(keyBytes) != len(key) {
		return fmt.Errorf("Incorrect key length: %d (want %d)", len(keyBytes), len(key))
	}
	copy(key[:], keyBytes)

	tombBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	plaintext, ok := secretbox.Open(nil, tombBytes, &nonce, &key)
	if !ok {
		return errors.New("Incorrect key")
	}

	c.stateLock, err = stateFile.Lock(true /* create */)
	if c.stateLock == nil && err == nil {
		return errors.New("Output statefile is locked.")
	}
	if err != nil {
		return err
	}

	writerChan := make(chan disk.NewState)
	writerDone := make(chan struct{})
	go stateFile.StartWriter(writerChan, writerDone)

	writerChan <- disk.NewState{State: plaintext}
	close(writerChan)
	<-writerDone

	return nil
}

func (c *client) receiveHook() {
	if c.receiveHookCommand != "" {
		cmd := exec.Command(c.receiveHookCommand)
		go func() {
			if err := cmd.Run(); err != nil {
				c.log.Errorf("Failed to run receive hook command: %s", err.Error())
			}
		}()
	}
}
