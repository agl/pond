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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/ed25519"
	"github.com/agl/pond/bbssig"
	"github.com/agl/pond/client/disk"
	"github.com/agl/pond/panda"
	pond "github.com/agl/pond/protos"
)

const (
	// messageLifetime is the default amount of time for which we'll keep a
	// message. (Counting from the time that it was received.)
	messageLifetime = 7 * 24 * time.Hour
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
	// revocationUpdateChan is a channel that the network goroutine reads
	// from. It contains contact ids and group member keys for contacts who
	// have updated their signature group because of a revocation event.
	// The network goroutine needs to resign all pending messages for that
	// contact.
	revocationUpdateChan chan revocationUpdate

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
}

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
	createAccountUI() error
	keyPromptUI(stateFile *disk.StateFile) error
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
}

type revocationUpdate struct {
	// id contains the contact id that needs to be updated.
	id  uint64
	key *bbssig.MemberKey
	// generation contains the new (i.e. post update) generation number for
	// the contact.
	generation uint32
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

	decryptions map[uint64]*pendingDecryption
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

	lastDHPrivate    [32]byte
	currentDHPrivate [32]byte

	theirLastDHPublic    [32]byte
	theirCurrentDHPublic [32]byte
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

	pendingDetachments map[uint64]*pendingDetachment
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

// detectTor attempts to connect to port 9050 and 9150 on the local host and
// assumes that Tor is running on the first port that it finds to be open.
func (c *client) detectTor() bool {
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

func (c *client) loadUI() error {
	c.ui.initUI()

	c.torAddress = "127.0.0.1:9050" // default for dev mode.
	if !c.dev && !c.detectTor() {
		if err := c.ui.torPromptUI(); err != nil {
			return err
		}
	}

	c.ui.loadingUI()

	stateFile := &disk.StateFile{
		Path: c.stateFilename,
		Rand: c.rand,
		Log: func(format string, args ...interface{}) {
			c.log.Printf(format, args...)
		},
	}

	var newAccount bool
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

		c.groupPriv, err = bbssig.GenerateGroup(rand.Reader)
		if err != nil {
			panic(err)
		}
		pw, err := c.ui.createPassphraseUI()
		if err != nil {
			return err
		}
		c.ui.createErasureStorage(pw, stateFile)
		if err := c.ui.createAccountUI(); err != nil {
			return err
		}
		newAccount = true
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

	if newAccount {
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
	c.revocationUpdateChan = make(chan revocationUpdate, 8)

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

func (contact *Contact) processKeyExchange(kxsBytes []byte, testing bool) error {
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

	if len(kx.Dh) != len(contact.theirCurrentDHPublic) {
		return errors.New("invalid public DH value")
	}
	copy(contact.theirCurrentDHPublic[:], kx.Dh)

	contact.generation = *kx.Generation

	return nil
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
		if n != 0 {
			return n
		}
	}
	panic("unreachable")
}

func (c *client) newKeyExchange(contact *Contact) {
	var err error
	c.randBytes(contact.lastDHPrivate[:])
	c.randBytes(contact.currentDHPrivate[:])

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &contact.lastDHPrivate)
	if contact.groupKey, err = c.groupPriv.NewMember(c.rand); err != nil {
		panic(err)
	}

	kx := &pond.KeyExchange{
		PublicKey:      c.pub[:],
		IdentityPublic: c.identityPublic[:],
		Server:         proto.String(c.server),
		Dh:             pub[:],
		Group:          contact.groupKey.Group.Marshal(),
		GroupKey:       contact.groupKey.Marshal(),
		Generation:     proto.Uint32(c.generation),
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

type pandaUpdate struct {
	id         uint64
	err        error
	result     []byte
	serialised []byte
}
