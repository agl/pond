package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/ed25519"
	"github.com/agl/pond/bbssig"
	"github.com/agl/pond/client/disk"
	"github.com/agl/pond/client/tpm"
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
	colorDefault               = 0
	colorWhite                 = 0xffffff
	colorGray                  = 0xfafafa
	colorHighlight             = 0xffebcd
	colorSubline               = 0x999999
	colorHeaderBackground      = 0xececed
	colorHeaderForeground      = 0x777777
	colorHeaderForegroundSmall = 0x7b7f83
	colorSep                   = 0xc9c9c9
	colorTitleForeground       = 0xdddddd
	colorBlack                 = 1
	colorRed                   = 0xff0000
	colorError                 = 0xff0000
)

const (
	fontLoadTitle   = "DejaVu Serif 30"
	fontLoadLarge   = "Arial Bold 30"
	fontListHeading = "Ariel Bold 11"
	fontListEntry   = "Liberation Sans 12"
	fontListSubline = "Liberation Sans 10"
	fontMainTitle   = "Arial 16"
	fontMainLabel   = "Arial Bold 9"
	fontMainBody    = "Arial 12"
	fontMainMono    = "Liberation Mono 10"
)

// uiState values are used for synchronisation with tests.
const (
	uiStateInvalid = iota
	uiStateLoading
	uiStateError
	uiStateMain
	uiStateCreateAccount
	uiStateCreatePassphrase
	uiStateNewContact
	uiStateNewContact2
	uiStateShowContact
	uiStateCompose
	uiStateOutbox
	uiStateShowIdentity
	uiStatePassphrase
	uiStateInbox
	uiStateLog
	uiStateRevocationProcessed
	uiStatePANDAComplete
	uiStateErasureStorage
)

const shortTimeFormat = "Jan _2 15:04"
const logTimeFormat = "Jan _2 15:04:05"
const keyExchangePEM = "POND KEY EXCHANGE"

// client is the main structure containing most of the client's state.
type client struct {
	// testing is true in unittests and disables some assertions that are
	// needed in the real world, but which make testing difficult.
	testing bool
	// autoFetch controls whether the network goroutine performs periodic
	// transactions or waits for outside prompting.
	autoFetch bool
	// newMeetingPlace is a function that returns a PANDA MeetingPlace. In
	// tests this can be overridden to return a testing meeting place.
	newMeetingPlace func() panda.MeetingPlace

	// stateFilename is the filename of the file on disk in which we
	// load/save our state.
	stateFilename string
	// stateLock protects the state against concurrent access by another
	// program.
	stateLock *disk.Lock

	ui UI
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

	inboxUI, outboxUI, contactsUI, clientUI, draftsUI *listUI

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
	// pandaShutdownChan is used to signal to the PANDA goroutines that the
	// client is stopping and that they should save state.
	pandaShutdownChan chan bool
	// pandaWaitGroup is incremented for each running PANDA goroutine.
	pandaWaitGroup sync.WaitGroup
}

type messageSendResult struct {
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
}

func (c *client) errorUI(errorText string, bgColor uint32) {
	ui := EventBox{
		widgetBase: widgetBase{background: bgColor, expand: true, fill: true},
		child: Label{
			widgetBase: widgetBase{
				foreground: colorBlack,
				font:       "Ariel Bold 12",
			},
			text:   errorText,
			xAlign: 0.5,
			yAlign: 0.5,
		},
	}
	c.log.Printf("Fatal error: %s", errorText)
	c.ui.Actions() <- SetBoxContents{name: "body", child: ui}
	c.ui.Actions() <- UIState{uiStateError}
	c.ui.Signal()
	if !c.testing {
		select {
		case _, ok := <-c.ui.Events():
			if !ok {
				// User asked to close the window.
				close(c.ui.Actions())
				select {}
			}
		}
	}
}

func (c *client) loadUI() {
	ui := VBox{
		widgetBase: widgetBase{
			background: colorWhite,
		},
		children: []Widget{
			EventBox{
				widgetBase: widgetBase{background: 0x333355},
				child: HBox{
					children: []Widget{
						Label{
							widgetBase: widgetBase{
								foreground: colorWhite,
								padding:    10,
								font:       fontLoadTitle,
							},
							text: "Pond",
						},
					},
				},
			},
			HBox{
				widgetBase: widgetBase{
					name:    "body",
					padding: 30,
					expand:  true,
					fill:    true,
				},
			},
		},
	}
	c.ui.Actions() <- Reset{ui}

	loading := EventBox{
		widgetBase: widgetBase{expand: true, fill: true},
		child: Label{
			widgetBase: widgetBase{
				foreground: colorTitleForeground,
				font:       fontLoadLarge,
			},
			text:   "Loading...",
			xAlign: 0.5,
			yAlign: 0.5,
		},
	}

	c.ui.Actions() <- SetBoxContents{name: "body", child: loading}
	c.ui.Actions() <- UIState{uiStateLoading}
	c.ui.Signal()

	stateFile := &disk.StateFile{
		Path: c.stateFilename,
		Rand: c.rand,
		Log:  c.log.Printf,
	}

	var newAccount bool
	var err error
	if c.stateLock, err = stateFile.Lock(false /* don't create */); err == nil && c.stateLock == nil {
		c.errorUI("State file locked by another process. Waiting for lock.", colorDefault)
		c.log.Errorf("Waiting for locked state file")

		for {
			if c.stateLock, err = stateFile.Lock(false /* don't create */); c.stateLock != nil {
				break
			}
			select {
			case _, ok := <-c.ui.Events():
				if !ok {
					// User asked to close the window.
					close(c.ui.Actions())
					select {}
				}
			case <-time.After(1 * time.Second):
				break
			}
		}
	} else if err == nil {
	} else if os.IsNotExist(err) {
		newAccount = true
	} else {
		c.errorUI(err.Error(), colorError)
		c.ShutdownAndSuspend()
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
		pw := c.createPassphraseUI()
		c.createErasureStorage(pw, stateFile)
		c.createAccountUI()
		newAccount = true
	} else {
		// First try with zero key.
		err := c.loadState(stateFile, "")
		for err == disk.BadPasswordError {
			// That didn't work, try prompting for a key.
			err = c.keyPromptUI(stateFile)
		}
		if err != nil {
			// Fatal error loading state. Abort.
			c.errorUI(err.Error(), colorError)
			c.ShutdownAndSuspend()
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
			c.errorUI(err.Error(), colorError)
			c.ShutdownAndSuspend()
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
		go c.runPANDA(contact.pandaKeyExchange, contact.id, contact.name)
	}

	c.mainUI()
}

func (c *client) DeselectAll() {
	c.inboxUI.Deselect()
	c.outboxUI.Deselect()
	c.contactsUI.Deselect()
	c.clientUI.Deselect()
	c.draftsUI.Deselect()
}

var rightPlaceholderUI = EventBox{
	widgetBase: widgetBase{background: colorGray, name: "right"},
	child: Label{
		widgetBase: widgetBase{
			foreground: colorTitleForeground,
			font:       fontLoadLarge,
		},
		text:   "Pond",
		xAlign: 0.5,
		yAlign: 0.5,
	},
}

func (c *client) updateWindowTitle() {
	unreadCount := 0

	for _, msg := range c.inbox {
		if msg.message != nil && !msg.read && len(msg.message.Body) > 0 {
			unreadCount++
		}
	}

	if unreadCount == 0 {
		c.ui.Actions() <- SetTitle{"Pond"}
	} else {
		c.ui.Actions() <- SetTitle{fmt.Sprintf("Pond (%d)", unreadCount)}
	}
	c.ui.Signal()
}

func (c *client) mainUI() {
	ui := Paned{
		left: Scrolled{
			viewport: true,
			child: EventBox{
				widgetBase: widgetBase{background: colorGray},
				child: VBox{
					children: []Widget{
						EventBox{
							widgetBase: widgetBase{background: colorHeaderBackground},
							child: Label{
								widgetBase: widgetBase{
									foreground: colorHeaderForegroundSmall,
									padding:    10,
									font:       fontListHeading,
								},
								xAlign: 0.5,
								text:   "Inbox",
							},
						},
						EventBox{widgetBase: widgetBase{height: 1, background: colorSep}},
						VBox{widgetBase: widgetBase{name: "inboxVbox"}},

						EventBox{
							widgetBase: widgetBase{background: colorHeaderBackground},
							child: Label{
								widgetBase: widgetBase{
									foreground: colorHeaderForegroundSmall,
									padding:    10,
									font:       fontListHeading,
								},
								xAlign: 0.5,
								text:   "Outbox",
							},
						},
						EventBox{widgetBase: widgetBase{height: 1, background: colorSep}},
						HBox{
							widgetBase: widgetBase{padding: 6},
							children: []Widget{
								HBox{widgetBase: widgetBase{expand: true}},
								HBox{
									widgetBase: widgetBase{padding: 8},
									children: []Widget{
										VBox{
											widgetBase: widgetBase{padding: 8},
											children: []Widget{
												Button{
													widgetBase: widgetBase{width: 100, name: "compose"},
													text:       "Compose",
												},
											},
										},
									},
								},
								HBox{widgetBase: widgetBase{expand: true}},
							},
						},
						VBox{widgetBase: widgetBase{name: "outboxVbox"}},

						EventBox{
							widgetBase: widgetBase{background: colorHeaderBackground},
							child: Label{
								widgetBase: widgetBase{
									foreground: colorHeaderForegroundSmall,
									padding:    10,
									font:       fontListHeading,
								},
								xAlign: 0.5,
								text:   "Drafts",
							},
						},
						EventBox{widgetBase: widgetBase{height: 1, background: colorSep}},
						VBox{widgetBase: widgetBase{name: "draftsVbox"}},

						EventBox{
							widgetBase: widgetBase{background: colorHeaderBackground},
							child: Label{
								widgetBase: widgetBase{
									foreground: colorHeaderForegroundSmall,
									padding:    10,
									font:       fontListHeading,
								},
								xAlign: 0.5,
								text:   "Contacts",
							},
						},
						EventBox{widgetBase: widgetBase{height: 1, background: colorSep}},
						HBox{
							widgetBase: widgetBase{padding: 6},
							children: []Widget{
								HBox{widgetBase: widgetBase{expand: true}},
								HBox{
									widgetBase: widgetBase{padding: 8},
									children: []Widget{
										VBox{
											widgetBase: widgetBase{padding: 8},
											children: []Widget{
												Button{
													widgetBase: widgetBase{width: 100, name: "newcontact"},
													text:       "Add",
												},
											},
										},
									},
								},
								HBox{widgetBase: widgetBase{expand: true}},
							},
						},
						VBox{widgetBase: widgetBase{name: "contactsVbox"}},

						EventBox{
							widgetBase: widgetBase{background: colorHeaderBackground},
							child: Label{
								widgetBase: widgetBase{
									foreground: colorHeaderForegroundSmall,
									padding:    10,
									font:       fontListHeading,
								},
								xAlign: 0.5,
								text:   "Client",
							},
						},
						EventBox{widgetBase: widgetBase{height: 1, background: colorSep}},
						VBox{
							widgetBase: widgetBase{name: "clientVbox"},
						},
					},
				},
			},
		},
		right: Scrolled{
			horizontal: true,
			viewport:   true,
			child:      rightPlaceholderUI,
		},
	}

	c.ui.Actions() <- Reset{ui}
	c.ui.Signal()

	c.contactsUI = &listUI{
		ui:       c.ui,
		vboxName: "contactsVbox",
	}

	for id, contact := range c.contacts {
		subline := ""
		if contact.isPending {
			subline = "pending"
		}
		c.contactsUI.Add(id, contact.name, subline, indicatorNone)
	}

	c.inboxUI = &listUI{
		ui:       c.ui,
		vboxName: "inboxVbox",
	}

	for _, msg := range c.inbox {
		var subline string
		i := indicatorNone

		if msg.message == nil {
			subline = "pending"
		} else {
			if len(msg.message.Body) == 0 {
				continue
			}
			if !msg.read {
				i = indicatorBlue
			}
			subline = time.Unix(*msg.message.Time, 0).Format(shortTimeFormat)
		}
		fromString := "Home Server"
		if msg.from != 0 {
			fromString = c.contacts[msg.from].name
		}
		c.inboxUI.Add(msg.id, fromString, subline, i)
	}
	c.updateWindowTitle()

	c.outboxUI = &listUI{
		ui:       c.ui,
		vboxName: "outboxVbox",
	}

	for _, msg := range c.outbox {
		if msg.revocation {
			c.outboxUI.Add(msg.id, "Revocation", msg.created.Format(shortTimeFormat), msg.indicator())
			c.outboxUI.SetInsensitive(msg.id)
			continue
		}
		if len(msg.message.Body) > 0 {
			subline := msg.created.Format(shortTimeFormat)
			c.outboxUI.Add(msg.id, c.contacts[msg.to].name, subline, msg.indicator())
		}
	}

	c.draftsUI = &listUI{
		ui:       c.ui,
		vboxName: "draftsVbox",
	}

	for _, draft := range c.drafts {
		to := "Unknown"
		if draft.to != 0 {
			to = c.contacts[draft.to].name
		}
		subline := draft.created.Format(shortTimeFormat)
		c.draftsUI.Add(draft.id, to, subline, indicatorNone)
	}

	c.clientUI = &listUI{
		ui:       c.ui,
		vboxName: "clientVbox",
	}
	const (
		clientUIIdentity = iota + 1
		clientUIActivity
	)
	c.clientUI.Add(clientUIIdentity, "Identity", "", indicatorNone)
	c.clientUI.Add(clientUIActivity, "Activity Log", "", indicatorNone)

	c.ui.Actions() <- UIState{uiStateMain}
	c.ui.Signal()

	var nextEvent interface{}
	for {
		event := nextEvent
		nextEvent = nil
		if event == nil {
			event, _ = c.nextEvent()
		}
		if event == nil {
			continue
		}

		c.DeselectAll()
		if id, ok := c.inboxUI.Event(event); ok {
			c.inboxUI.Select(id)
			nextEvent = c.showInbox(id)
			continue
		}
		if id, ok := c.outboxUI.Event(event); ok {
			c.outboxUI.Select(id)
			nextEvent = c.showOutbox(id)
			continue
		}
		if id, ok := c.contactsUI.Event(event); ok {
			c.contactsUI.Select(id)
			nextEvent = c.showContact(id)
			continue
		}
		if id, ok := c.clientUI.Event(event); ok {
			c.clientUI.Select(id)
			switch id {
			case clientUIIdentity:
				nextEvent = c.identityUI()
			case clientUIActivity:
				nextEvent = c.logUI()
			default:
				panic("bad clientUI event")
			}
			continue
		}
		if id, ok := c.draftsUI.Event(event); ok {
			c.draftsUI.Select(id)
			nextEvent = c.composeUI(c.drafts[id], nil)
		}

		click, ok := event.(Click)
		if !ok {
			continue
		}
		switch click.name {
		case "newcontact":
			nextEvent = c.newContactUI(nil)
		case "compose":
			nextEvent = c.composeUI(nil, nil)
		}
	}
}

// listUI manages the sections in the left-hand side list. It contains a number
// of items, which may have subheadlines and indicators (coloured dots).
type listUI struct {
	ui       UI
	vboxName string
	entries  []listItem
	selected uint64
	nextId   int
}

type listItem struct {
	id                                                           uint64
	name, sepName, boxName, imageName, lineName, sublineTextName string
	insensitive                                                  bool
}

func (cs *listUI) Event(event interface{}) (uint64, bool) {
	if click, ok := event.(Click); ok {
		for _, entry := range cs.entries {
			if click.name == entry.boxName {
				if entry.insensitive {
					return 0, false
				}
				return entry.id, true
			}
		}
	}

	return 0, false
}

func (cs *listUI) Add(id uint64, name, subline string, indicator Indicator) {
	c := listItem{
		id:              id,
		name:            name,
		sepName:         cs.newIdent(),
		boxName:         cs.newIdent(),
		imageName:       cs.newIdent(),
		lineName:        cs.newIdent(),
		sublineTextName: cs.newIdent(),
	}
	cs.entries = append(cs.entries, c)
	index := len(cs.entries) - 1

	if index > 0 {
		// Add the separator bar.
		cs.ui.Actions() <- AddToBox{
			box:   cs.vboxName,
			pos:   index*2 - 1,
			child: EventBox{widgetBase: widgetBase{height: 1, background: 0xe5e6e6, name: c.sepName}},
		}
	}

	children := []Widget{
		HBox{
			widgetBase: widgetBase{padding: 1},
			children: []Widget{
				Label{
					widgetBase: widgetBase{
						name:    c.lineName,
						padding: 5,
						font:    fontListEntry,
					},
					text: name,
				},
			},
		},
	}

	var sublineChildren []Widget

	if len(subline) > 0 {
		sublineChildren = append(sublineChildren, Label{
			widgetBase: widgetBase{
				padding:    5,
				foreground: colorSubline,
				font:       fontListSubline,
				name:       c.sublineTextName,
			},
			text: subline,
		})
	}

	sublineChildren = append(sublineChildren, Image{
		widgetBase: widgetBase{
			padding: 4,
			expand:  true,
			fill:    true,
			name:    c.imageName,
		},
		image:  indicator,
		xAlign: 1,
		yAlign: 0.5,
	})

	children = append(children, HBox{
		widgetBase: widgetBase{padding: 1},
		children:   sublineChildren,
	})

	cs.ui.Actions() <- AddToBox{
		box: cs.vboxName,
		pos: index * 2,
		child: EventBox{
			widgetBase: widgetBase{name: c.boxName, background: colorGray},
			child:      VBox{children: children},
		},
	}
	cs.ui.Signal()
}

func (cs *listUI) SetInsensitive(id uint64) {
	for i, entry := range cs.entries {
		if entry.id == id {
			cs.entries[i].insensitive = true
		}
	}
}

func (cs *listUI) Remove(id uint64) {
	for i, entry := range cs.entries {
		if entry.id == id {
			if i > 0 {
				cs.ui.Actions() <- Destroy{name: entry.sepName}
			}
			cs.ui.Actions() <- Destroy{name: entry.boxName}
			cs.ui.Signal()
			if cs.selected == id {
				cs.selected = 0
			}
			return
		}
	}

	panic("unknown id passed to Remove")
}

func (cs *listUI) Deselect() {
	if cs.selected == 0 {
		return
	}

	var currentlySelected string

	for _, entry := range cs.entries {
		if entry.id == cs.selected {
			currentlySelected = entry.boxName
			break
		}
	}

	cs.ui.Actions() <- SetBackground{name: currentlySelected, color: colorGray}
	cs.selected = 0
	cs.ui.Signal()
}

func (cs *listUI) Select(id uint64) {
	if id == cs.selected {
		return
	}

	var currentlySelected, newSelected string

	for _, entry := range cs.entries {
		if entry.id == cs.selected {
			currentlySelected = entry.boxName
		} else if entry.id == id {
			newSelected = entry.boxName
		}

		if len(currentlySelected) > 0 && len(newSelected) > 0 {
			break
		}
	}

	if len(newSelected) == 0 {
		panic("internal error")
	}

	if len(currentlySelected) > 0 {
		cs.ui.Actions() <- SetBackground{name: currentlySelected, color: colorGray}
	}
	cs.ui.Actions() <- SetBackground{name: newSelected, color: colorHighlight}
	cs.selected = id
	cs.ui.Signal()
}

func (cs *listUI) SetIndicator(id uint64, indicator Indicator) {
	for _, entry := range cs.entries {
		if entry.id == id {
			cs.ui.Actions() <- SetImage{name: entry.imageName, image: indicator}
			cs.ui.Signal()
			break
		}
	}
}

func (cs *listUI) SetLine(id uint64, line string) {
	for _, entry := range cs.entries {
		if entry.id == id {
			cs.ui.Actions() <- SetText{name: entry.lineName, text: line}
			cs.ui.Signal()
			break
		}
	}
}

func (cs *listUI) SetSubline(id uint64, subline string) {
	for _, entry := range cs.entries {
		if entry.id == id {
			if len(subline) > 0 {
				cs.ui.Actions() <- SetText{name: entry.sublineTextName, text: subline}
			} else {
				cs.ui.Actions() <- Destroy{name: entry.sublineTextName}
			}
			cs.ui.Signal()
			break
		}
	}
}

func (cs *listUI) newIdent() string {
	id := cs.vboxName + "-" + strconv.Itoa(cs.nextId)
	cs.nextId++
	return id
}

// usageString returns a description of the amount of space taken up by a body
// with the given contents and a bool indicating overflow.
func usageString(draft *Draft) (string, bool) {
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

	s := fmt.Sprintf("%d of %d bytes", len(serialized), pond.MaxSerializedMessage)
	return s, len(serialized) > pond.MaxSerializedMessage
}

func widgetForAttachment(id uint64, label string, isError bool, extraWidgets []Widget) Widget {
	var labelName string
	var labelColor uint32
	if isError {
		labelName = fmt.Sprintf("attachment-error-%x", id)
		labelColor = colorRed
	} else {
		labelName = fmt.Sprintf("attachment-label-%x", id)
	}
	return Frame{
		widgetBase: widgetBase{
			name:    fmt.Sprintf("attachment-frame-%x", id),
			padding: 1,
		},
		child: VBox{
			widgetBase: widgetBase{
				name: fmt.Sprintf("attachment-vbox-%x", id),
			},
			children: append([]Widget{
				HBox{
					children: []Widget{
						Label{
							widgetBase: widgetBase{
								padding:    2,
								foreground: labelColor,
								name:       labelName,
							},
							yAlign: 0.5,
							text:   label,
						},
						VBox{
							widgetBase: widgetBase{expand: true, fill: true},
						},
						Button{
							widgetBase: widgetBase{name: fmt.Sprintf("remove-%x", id)},
							image:      indicatorRemove,
						},
					},
				},
			}, extraWidgets...),
		},
	}
}

type DetachmentUI interface {
	IsValid(id uint64) bool
	ProgressName(id uint64) string
	VBoxName(id uint64) string
	OnFinal(id uint64)
	OnSuccess(id uint64, detachment *pond.Message_Detachment)
}

type ComposeDetachmentUI struct {
	draft       *Draft
	detachments map[uint64]int
	ui          UI
	final       func()
}

func (i ComposeDetachmentUI) IsValid(id uint64) bool {
	_, ok := i.draft.pendingDetachments[id]
	return ok
}

func (i ComposeDetachmentUI) ProgressName(id uint64) string {
	return fmt.Sprintf("attachment-progress-%x", id)
}

func (i ComposeDetachmentUI) VBoxName(id uint64) string {
	return fmt.Sprintf("attachment-vbox-%x", id)
}

func (i ComposeDetachmentUI) OnFinal(id uint64) {
	delete(i.draft.pendingDetachments, id)
	i.final()
}

func (i ComposeDetachmentUI) OnSuccess(id uint64, detachment *pond.Message_Detachment) {
	i.detachments[id] = len(i.draft.detachments)
	i.draft.detachments = append(i.draft.detachments, detachment)
}

// maybeProcessDetachmentMsg is called to process a possible message from a
// background, detachment task. It returns true if event was handled.
func (c *client) maybeProcessDetachmentMsg(event interface{}, ui DetachmentUI) bool {
	if derr, ok := event.(DetachmentError); ok {
		id := derr.id
		if !ui.IsValid(id) {
			return true
		}
		c.ui.Actions() <- Destroy{name: ui.ProgressName(id)}
		c.ui.Actions() <- Append{
			name: ui.VBoxName(id),
			children: []Widget{
				Label{
					widgetBase: widgetBase{
						foreground: colorRed,
					},
					text: derr.err.Error(),
				},
			},
		}
		ui.OnFinal(id)
		c.ui.Signal()
		return true
	}
	if prog, ok := event.(DetachmentProgress); ok {
		id := prog.id
		if !ui.IsValid(id) {
			return true
		}
		if prog.total == 0 {
			return true
		}
		f := float64(prog.done) / float64(prog.total)
		if f > 1 {
			f = 1
		}
		c.ui.Actions() <- SetProgress{
			name:     ui.ProgressName(id),
			s:        prog.status,
			fraction: f,
		}
		c.ui.Signal()
		return true
	}
	if complete, ok := event.(DetachmentComplete); ok {
		id := complete.id
		if !ui.IsValid(id) {
			return true
		}
		c.ui.Actions() <- Destroy{
			name: ui.ProgressName(id),
		}
		ui.OnFinal(id)
		ui.OnSuccess(id, complete.detachment)
		c.ui.Signal()
		return true
	}

	return false
}

func (c *client) updateUsage(validContactSelected bool, draft *Draft) bool {
	usageMessage, over := usageString(draft)
	c.ui.Actions() <- SetText{name: "usage", text: usageMessage}
	color := uint32(colorBlack)
	if over {
		color = colorRed
		c.ui.Actions() <- Sensitive{name: "send", sensitive: false}
	} else if validContactSelected {
		c.ui.Actions() <- Sensitive{name: "send", sensitive: true}
	}
	c.ui.Actions() <- SetForeground{name: "usage", foreground: color}
	return over
}

func (c *client) composeUI(draft *Draft, inReplyTo *InboxMessage) interface{} {
	if draft != nil && inReplyTo != nil {
		panic("draft and inReplyTo both set")
	}

	var contactNames []string
	for _, contact := range c.contacts {
		if !contact.revokedUs {
			contactNames = append(contactNames, contact.name)
		}
	}

	var preSelected string
	if inReplyTo != nil {
		if from, ok := c.contacts[inReplyTo.from]; ok {
			preSelected = from.name
		}
	}

	attachments := make(map[uint64]int)
	detachments := make(map[uint64]int)

	if draft != nil {
		if to, ok := c.contacts[draft.to]; ok {
			preSelected = to.name
		}
		for i := range draft.attachments {
			attachments[c.randId()] = i
		}
		for i := range draft.detachments {
			detachments[c.randId()] = i
		}
	}

	if draft == nil {
		var replyToId, contactId uint64
		from := preSelected

		if inReplyTo != nil {
			replyToId = inReplyTo.id
			contactId = inReplyTo.from
		}
		if len(preSelected) == 0 {
			from = "Unknown"
		}

		draft = &Draft{
			id:        c.randId(),
			inReplyTo: replyToId,
			to:        contactId,
			created:   time.Now(),
		}

		c.draftsUI.Add(draft.id, from, draft.created.Format(shortTimeFormat), indicatorNone)
		c.draftsUI.Select(draft.id)
		c.drafts[draft.id] = draft
	}

	initialUsageMessage, overSize := usageString(draft)
	validContactSelected := len(preSelected) > 0

	lhs := VBox{
		children: []Widget{
			HBox{
				widgetBase: widgetBase{padding: 2},
				children: []Widget{
					Label{
						widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, padding: 10},
						text:       "TO",
						yAlign:     0.5,
					},
					Combo{
						widgetBase: widgetBase{
							name:        "to",
							insensitive: len(preSelected) > 0 && inReplyTo != nil,
						},
						labels:      contactNames,
						preSelected: preSelected,
					},
				},
			},
			HBox{
				widgetBase: widgetBase{padding: 2},
				children: []Widget{
					Label{
						widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, padding: 10},
						text:       "SIZE",
						yAlign:     0.5,
					},
					Label{
						widgetBase: widgetBase{name: "usage"},
						text:       initialUsageMessage,
					},
				},
			},
			HBox{
				widgetBase: widgetBase{padding: 0},
				children: []Widget{
					Label{
						widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, padding: 10},
						text:       "ATTACHMENTS",
						yAlign:     0.5,
					},
					Button{
						widgetBase: widgetBase{name: "attach", font: "Liberation Sans 8"},
						image:      indicatorAdd,
					},
				},
			},
			HBox{
				widgetBase: widgetBase{padding: 0},
				children: []Widget{
					VBox{
						widgetBase: widgetBase{name: "filesvbox", padding: 25},
					},
				},
			},
		},
	}
	rhs := VBox{
		widgetBase: widgetBase{padding: 5},
		children: []Widget{
			Button{
				widgetBase: widgetBase{name: "send", insensitive: !validContactSelected, padding: 2},
				text:       "Send",
			},
			Button{
				widgetBase: widgetBase{name: "discard", padding: 2},
				text:       "Discard",
			},
		},
	}
	ui := VBox{
		children: []Widget{
			EventBox{
				widgetBase: widgetBase{background: colorHeaderBackground},
				child: VBox{
					children: []Widget{
						HBox{
							widgetBase: widgetBase{padding: 10},
							children: []Widget{
								Label{
									widgetBase: widgetBase{font: fontMainTitle, padding: 10, foreground: colorHeaderForeground},
									text:       "COMPOSE",
								},
							},
						},
					},
				},
			},
			EventBox{widgetBase: widgetBase{height: 1, background: colorSep}},
			HBox{
				children: []Widget{
					lhs,
					Label{
						widgetBase: widgetBase{expand: true, fill: true},
					},
					rhs,
				},
			},
			Scrolled{
				widgetBase: widgetBase{expand: true, fill: true},
				horizontal: true,
				child: TextView{
					widgetBase:     widgetBase{expand: true, fill: true, name: "body"},
					editable:       true,
					wrap:           true,
					updateOnChange: true,
					spellCheck:     true,
					text:           draft.body,
				},
			},
		},
	}

	c.ui.Actions() <- SetChild{name: "right", child: ui}

	if draft.pendingDetachments == nil {
		draft.pendingDetachments = make(map[uint64]*pendingDetachment)
	}

	var initialAttachmentChildren []Widget
	for id, index := range attachments {
		attachment := draft.attachments[index]
		initialAttachmentChildren = append(initialAttachmentChildren, widgetForAttachment(id, fmt.Sprintf("%s (%d bytes)", *attachment.Filename, len(attachment.Contents)), false, nil))
	}
	for id, index := range detachments {
		detachment := draft.detachments[index]
		initialAttachmentChildren = append(initialAttachmentChildren, widgetForAttachment(id, fmt.Sprintf("%s (%d bytes, external)", *detachment.Filename, *detachment.Size), false, nil))
	}
	for id, pending := range draft.pendingDetachments {
		initialAttachmentChildren = append(initialAttachmentChildren, widgetForAttachment(id, fmt.Sprintf("%s (%d bytes, external)", filepath.Base(pending.path), pending.size), false, []Widget{
			Progress{
				widgetBase: widgetBase{
					name: fmt.Sprintf("attachment-progress-%x", id),
				},
			},
		}))
	}

	if len(initialAttachmentChildren) > 0 {
		c.ui.Actions() <- Append{
			name:     "filesvbox",
			children: initialAttachmentChildren,
		}
	}

	detachmentUI := ComposeDetachmentUI{draft, detachments, c.ui, func() {
		overSize = c.updateUsage(validContactSelected, draft)
	}}

	c.ui.Actions() <- UIState{uiStateCompose}
	c.ui.Signal()

	for {
		event, wanted := c.nextEvent()
		if wanted {
			return event
		}

		if update, ok := event.(Update); ok {
			overSize = c.updateUsage(validContactSelected, draft)
			draft.body = update.text
			c.ui.Signal()
			continue
		}

		if open, ok := event.(OpenResult); ok && open.ok && open.arg == nil {
			// Opening a file for an attachment.
			contents, size, err := func(path string) (contents []byte, size int64, err error) {
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
			}(open.path)

			base := filepath.Base(open.path)
			id := c.randId()

			var label string
			var extraWidgets []Widget
			if err != nil {
				label = base + ": " + err.Error()
			} else if size > 0 {
				// Oversize attachment.
				label = fmt.Sprintf("%s (%d bytes, external)", base, size)
				extraWidgets = []Widget{VBox{
					widgetBase: widgetBase{
						name: fmt.Sprintf("attachment-addi-%x", id),
					},
					children: []Widget{
						Label{
							widgetBase: widgetBase{
								padding: 4,
							},
							text: "This file is too large to send via Pond directly. Instead, this Pond message can contain the encryption key for the file and the encrypted file can be transported via a non-Pond mechanism.",
							wrap: 300,
						},
						HBox{
							children: []Widget{
								Button{
									widgetBase: widgetBase{
										name: fmt.Sprintf("attachment-convert-%x", id),
									},
									text: "Save Encrypted",
								},
								Button{
									widgetBase: widgetBase{
										name: fmt.Sprintf("attachment-upload-%x", id),
									},
									text: "Upload",
								},
							},
						},
					},
				}}

				draft.pendingDetachments[id] = &pendingDetachment{
					path: open.path,
					size: size,
				}
			} else {
				label = fmt.Sprintf("%s (%d bytes)", base, len(contents))
				a := &pond.Message_Attachment{
					Filename: proto.String(filepath.Base(open.path)),
					Contents: contents,
				}
				attachments[id] = len(draft.attachments)
				draft.attachments = append(draft.attachments, a)
			}

			c.ui.Actions() <- Append{
				name: "filesvbox",
				children: []Widget{
					widgetForAttachment(id, label, err != nil, extraWidgets),
				},
			}
			overSize = c.updateUsage(validContactSelected, draft)
			c.ui.Signal()
		}
		if open, ok := event.(OpenResult); ok && open.ok && open.arg != nil {
			// Saving a detachment.
			id := open.arg.(uint64)
			c.ui.Actions() <- Destroy{name: fmt.Sprintf("attachment-addi-%x", id)}
			c.ui.Actions() <- Append{
				name: fmt.Sprintf("attachment-vbox-%x", id),
				children: []Widget{
					Progress{
						widgetBase: widgetBase{
							name: fmt.Sprintf("attachment-progress-%x", id),
						},
					},
				},
			}
			draft.pendingDetachments[id].cancel = c.startEncryption(id, open.path, draft.pendingDetachments[id].path)
			c.ui.Signal()
		}

		if c.maybeProcessDetachmentMsg(event, detachmentUI) {
			continue
		}

		click, ok := event.(Click)
		if !ok {
			continue
		}
		if click.name == "attach" {
			c.ui.Actions() <- FileOpen{
				title: "Attach File",
			}
			c.ui.Signal()
			continue
		}
		if click.name == "to" {
			selected := click.combos["to"]
			if len(selected) > 0 {
				validContactSelected = true
			}
			for _, contact := range c.contacts {
				if contact.name == selected {
					draft.to = contact.id
				}
			}
			c.draftsUI.SetLine(draft.id, selected)
			if validContactSelected && !overSize {
				c.ui.Actions() <- Sensitive{name: "send", sensitive: true}
				c.ui.Signal()
			}
			continue
		}
		if click.name == "discard" {
			c.draftsUI.Remove(draft.id)
			delete(c.drafts, draft.id)
			c.save()
			c.ui.Actions() <- SetChild{name: "right", child: rightPlaceholderUI}
			c.ui.Actions() <- UIState{uiStateMain}
			c.ui.Signal()
			return nil
		}
		if strings.HasPrefix(click.name, "remove-") {
			// One of the attachment remove buttons.
			id, err := strconv.ParseUint(click.name[7:], 16, 64)
			if err != nil {
				panic(click.name)
			}
			c.ui.Actions() <- Destroy{name: "attachment-frame-" + click.name[7:]}
			if index, ok := attachments[id]; ok {
				draft.attachments = append(draft.attachments[:index], draft.attachments[index+1:]...)
				delete(attachments, id)
			}
			if detachment, ok := draft.pendingDetachments[id]; ok {
				if detachment.cancel != nil {
					detachment.cancel()
				}
				delete(draft.pendingDetachments, id)
			}
			if index, ok := detachments[id]; ok {
				draft.detachments = append(draft.detachments[:index], draft.detachments[index+1:]...)
				delete(detachments, id)
			}
			overSize = c.updateUsage(validContactSelected, draft)
			c.ui.Signal()
			continue
		}
		const convertPrefix = "attachment-convert-"
		if strings.HasPrefix(click.name, convertPrefix) {
			// One of the attachment "Save Encrypted" buttons.
			idStr := click.name[len(convertPrefix):]
			id, err := strconv.ParseUint(idStr, 16, 64)
			if err != nil {
				panic(click.name)
			}
			c.ui.Actions() <- FileOpen{
				save:  true,
				title: "Save encrypted file",
				arg:   id,
			}
			c.ui.Signal()
		}
		const uploadPrefix = "attachment-upload-"
		if strings.HasPrefix(click.name, uploadPrefix) {
			idStr := click.name[len(uploadPrefix):]
			id, err := strconv.ParseUint(idStr, 16, 64)
			if err != nil {
				panic(click.name)
			}
			c.ui.Actions() <- Destroy{name: fmt.Sprintf("attachment-addi-%x", id)}
			c.ui.Actions() <- Append{
				name: fmt.Sprintf("attachment-vbox-%x", id),
				children: []Widget{
					Progress{
						widgetBase: widgetBase{
							name: fmt.Sprintf("attachment-progress-%x", id),
						},
					},
				},
			}
			draft.pendingDetachments[id].cancel = c.startUpload(id, draft.pendingDetachments[id].path)
			c.ui.Signal()
		}

		if click.name != "send" {
			continue
		}

		toName := click.combos["to"]
		if len(toName) == 0 {
			continue
		}

		var to *Contact
		for _, contact := range c.contacts {
			if contact.name == toName {
				to = contact
				break
			}
		}

		var nextDHPub [32]byte
		curve25519.ScalarBaseMult(&nextDHPub, &to.currentDHPrivate)

		var replyToId *uint64
		if inReplyTo != nil {
			replyToId = inReplyTo.message.Id
		}

		body := click.textViews["body"]
		// Zero length bodies are ACKs.
		if len(body) == 0 {
			body = " "
		}

		id := c.randId()
		err := c.send(to, &pond.Message{
			Id:               proto.Uint64(id),
			Time:             proto.Int64(time.Now().Unix()),
			Body:             []byte(body),
			BodyEncoding:     pond.Message_RAW.Enum(),
			InReplyTo:        replyToId,
			MyNextDh:         nextDHPub[:],
			Files:            draft.attachments,
			DetachedFiles:    draft.detachments,
			SupportedVersion: proto.Int32(protoVersion),
		})
		if err != nil {
			// TODO: handle this case better.
			println(err.Error())
			c.log.Errorf("Error sending message: %s", err)
			continue
		}
		if inReplyTo != nil {
			inReplyTo.acked = true
		}

		c.draftsUI.Remove(draft.id)
		delete(c.drafts, draft.id)

		c.save()

		c.outboxUI.Select(id)
		return c.showOutbox(id)
	}

	return nil
}

func (qm *queuedMessage) indicator() Indicator {
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
	}
	return indicatorRed
}

func (c *client) enqueue(m *queuedMessage) {
	c.queueMutex.Lock()
	defer c.queueMutex.Unlock()

	c.queue = append(c.queue, m)
}

func (c *client) sendAck(msg *InboxMessage) {
	to := c.contacts[msg.from]

	var nextDHPub [32]byte
	curve25519.ScalarBaseMult(&nextDHPub, &to.currentDHPrivate)

	id := c.randId()
	err := c.send(to, &pond.Message{
		Id:               proto.Uint64(id),
		Time:             proto.Int64(time.Now().Unix()),
		Body:             make([]byte, 0),
		BodyEncoding:     pond.Message_RAW.Enum(),
		MyNextDh:         nextDHPub[:],
		InReplyTo:        msg.message.Id,
		SupportedVersion: proto.Int32(protoVersion),
	})
	if err != nil {
		c.log.Errorf("Error sending message: %s", err)
	}
}

func maybeTruncate(s string) string {
	if runes := []rune(s); len(runes) > 30 {
		runes = runes[:30]
		runes = append(runes, 0x2026 /* ellipsis */)
		return string(runes)
	}
	return s
}

type InboxDetachmentUI struct {
	msg *InboxMessage
	ui  UI
}

func (i InboxDetachmentUI) IsValid(id uint64) bool {
	_, ok := i.msg.decryptions[id]
	return ok
}

func (i InboxDetachmentUI) ProgressName(id uint64) string {
	return fmt.Sprintf("detachment-progress-%d", i.msg.decryptions[id].index)
}

func (i InboxDetachmentUI) VBoxName(id uint64) string {
	return fmt.Sprintf("detachment-vbox-%d", i.msg.decryptions[id].index)
}

func (i InboxDetachmentUI) OnFinal(id uint64) {
	i.ui.Actions() <- Sensitive{
		name:      fmt.Sprintf("detachment-decrypt-%d", i.msg.decryptions[id].index),
		sensitive: true,
	}
	i.ui.Actions() <- Sensitive{
		name:      fmt.Sprintf("detachment-download-%d", i.msg.decryptions[id].index),
		sensitive: true,
	}
	delete(i.msg.decryptions, id)
}

func (i InboxDetachmentUI) OnSuccess(id uint64, detachment *pond.Message_Detachment) {
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "(not yet)"
	}
	return t.Format(time.RFC1123)
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

func (c *client) nextEvent() (event interface{}, wanted bool) {
	var ok bool
	select {
	case event, ok = <-c.ui.Events():
		if !ok {
			c.ShutdownAndSuspend()
		}
	case newMessage := <-c.newMessageChan:
		c.processNewMessage(newMessage)
		return
	case msr := <-c.messageSentChan:
		c.processMessageSent(msr)
		return
	case update := <-c.pandaChan:
		c.processPANDAUpdate(update)
		return
	case event = <-c.backgroundChan:
		break
	case <-c.log.updateChan:
		return
	}

	if _, ok := c.contactsUI.Event(event); ok {
		wanted = true
	}
	if _, ok := c.outboxUI.Event(event); ok {
		wanted = true
	}
	if _, ok := c.inboxUI.Event(event); ok {
		wanted = true
	}
	if _, ok := c.clientUI.Event(event); ok {
		wanted = true
	}
	if _, ok := c.draftsUI.Event(event); ok {
		wanted = true
	}
	if click, ok := event.(Click); ok {
		wanted = wanted || click.name == "newcontact" || click.name == "compose"
	}
	return
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

func (c *client) keyPromptUI(stateFile *disk.StateFile) error {
	ui := VBox{
		widgetBase: widgetBase{padding: 40, expand: true, fill: true, name: "vbox"},
		children: []Widget{
			Label{
				widgetBase: widgetBase{font: "DejaVu Sans 30"},
				text:       "Passphrase",
			},
			Label{
				widgetBase: widgetBase{
					padding: 20,
					font:    "DejaVu Sans 14",
				},
				text: "Please enter the passphrase used to encrypt Pond's state file. If you set a passphrase and forgot it, it cannot be recovered. You will have to start afresh.",
				wrap: 600,
			},
			HBox{
				spacing: 5,
				children: []Widget{
					Label{
						text:   "Passphrase:",
						yAlign: 0.5,
					},
					Entry{
						widgetBase: widgetBase{name: "pw"},
						width:      60,
						password:   true,
					},
				},
			},
			HBox{
				widgetBase: widgetBase{padding: 40},
				children: []Widget{
					Button{
						widgetBase: widgetBase{name: "next"},
						text:       "Next",
					},
				},
			},
			HBox{
				widgetBase: widgetBase{padding: 5},
				children: []Widget{
					Label{
						widgetBase: widgetBase{name: "status"},
					},
				},
			},
		},
	}

	c.ui.Actions() <- SetBoxContents{name: "body", child: ui}
	c.ui.Actions() <- SetFocus{name: "pw"}
	c.ui.Actions() <- UIState{uiStatePassphrase}
	c.ui.Signal()

	for {
		event, ok := <-c.ui.Events()
		if !ok {
			c.ShutdownAndSuspend()
		}

		click, ok := event.(Click)
		if !ok {
			continue
		}
		if click.name != "next" && click.name != "pw" {
			continue
		}

		pw, ok := click.entries["pw"]
		if !ok {
			panic("missing pw")
		}

		c.ui.Actions() <- Sensitive{name: "next", sensitive: false}
		c.ui.Signal()

		err := c.loadState(stateFile, pw)
		if err != disk.BadPasswordError {
			return err
		}

		c.ui.Actions() <- SetText{name: "status", text: "Incorrect passphrase or corrupt state file"}
		c.ui.Actions() <- SetEntry{name: "pw", text: ""}
		c.ui.Actions() <- Sensitive{name: "next", sensitive: true}
		c.ui.Signal()
	}

	return nil
}

func (c *client) createPassphraseUI() string {
	ui := VBox{
		widgetBase: widgetBase{padding: 40, expand: true, fill: true, name: "vbox"},
		children: []Widget{
			Label{
				widgetBase: widgetBase{font: "DejaVu Sans 30"},
				text:       "Set Passphrase",
			},
			Label{
				widgetBase: widgetBase{
					padding: 20,
					font:    "DejaVu Sans 14",
				},
				text: "Pond keeps private keys, messages etc on disk for a limited amount of time and that information can be encrypted with a passphrase. If you are comfortable with the security of your home directory, this passphrase can be empty and you won't be prompted for it again. If you set a passphrase and forget it, it cannot be recovered. You will have to start afresh.",
				wrap: 600,
			},
			HBox{
				spacing: 5,
				children: []Widget{
					Label{
						text:   "Passphrase:",
						yAlign: 0.5,
					},
					Entry{
						widgetBase: widgetBase{name: "pw"},
						width:      60,
						password:   true,
					},
				},
			},
			HBox{
				widgetBase: widgetBase{padding: 40},
				children: []Widget{
					Button{
						widgetBase: widgetBase{name: "next"},
						text:       "Next",
					},
				},
			},
		},
	}

	c.ui.Actions() <- SetBoxContents{name: "body", child: ui}
	c.ui.Actions() <- SetFocus{name: "pw"}
	c.ui.Actions() <- UIState{uiStateCreatePassphrase}
	c.ui.Signal()

	for {
		event, ok := <-c.ui.Events()
		if !ok {
			c.ShutdownAndSuspend()
		}

		click, ok := event.(Click)
		if !ok {
			continue
		}
		if click.name != "next" && click.name != "pw" {
			continue
		}

		pw, ok := click.entries["pw"]
		if !ok {
			panic("missing pw")
		}

		return pw
	}

	panic("unreachable")
}

func (c *client) createErasureStorage(pw string, stateFile *disk.StateFile) error {
	var tpmInfo string
	present := tpm.Present()
	if present {
		tpmInfo = "Your computer appears to have a TPM chip. Click below to try and use it. You'll need tcsd (the TPM daemon) running."
	} else {
		tpmInfo = "Your computer does not appear to have a TPM chip. Without one, it's possible that someone in physical possession of your computer and passphrase could extract old messages that should have been deleted. Using a computer with a TPM is strongly preferable until alternatives can be implemented."
	}

	ui := VBox{
		widgetBase: widgetBase{padding: 40, expand: true, fill: true, name: "vbox"},
		children: []Widget{
			Label{
				widgetBase: widgetBase{font: "DejaVu Sans 30"},
				text:       "Configure TPM",
			},
			Label{
				widgetBase: widgetBase{
					padding: 20,
					font:    "DejaVu Sans 14",
				},
				text: "It's very difficult to erase information on modern computers so Pond tries to use the TPM chip if possible.\n\n" + tpmInfo,
				wrap: 600,
			},
			HBox{
				children: []Widget{
					Button{
						widgetBase: widgetBase{name: "tpm"},
						text:       "Try to configure TPM",
					},
				},
			},
			TextView{
				widgetBase: widgetBase{name: "log", expand: true, fill: true},
				editable:   false,
			},
			Button{
				widgetBase: widgetBase{name: "continue"},
				text:       "Continue without TPM",
			},
		},
	}

	c.ui.Actions() <- SetBoxContents{name: "body", child: ui}
	c.ui.Actions() <- SetFocus{name: "tpm"}
	c.ui.Actions() <- UIState{uiStateErasureStorage}
	c.ui.Signal()

	var logText string

	tpm := disk.TPM{
		Log: func(format string, args ...interface{}) {
			c.log.Printf(format, args...)
			logText += fmt.Sprintf(format, args...) + "\n"
			c.ui.Actions() <- SetTextView{name: "log", text: logText}
			c.ui.Signal()
		},
		Rand: c.rand,
	}

NextEvent:
	for {
		event, ok := <-c.ui.Events()
		if !ok {
			c.ShutdownAndSuspend()
		}

		click, ok := event.(Click)
		if !ok {
			continue
		}

		switch click.name {
		case "continue":
			stateFile.Erasure = nil
			return stateFile.Create(pw)
		case "tpm":
			if len(logText) > 0 {
				c.ui.Actions() <- SetTextView{name: "log", text: ""}
				c.ui.Signal()
				logText = ""
				time.Sleep(300 * time.Millisecond)
			}

			stateFile.Erasure = &tpm
			c.ui.Actions() <- Sensitive{name: "tpm", sensitive: false}
			c.ui.Actions() <- Sensitive{name: "continue", sensitive: false}
			c.ui.Signal()
			if err := stateFile.Create(pw); err != nil {
				tpm.Log("Setup failed with error: %s", err)
				tpm.Log("You can click the button to try again")
				c.ui.Actions() <- Sensitive{name: "tpm", sensitive: true}
				c.ui.Actions() <- Sensitive{name: "continue", sensitive: true}
				c.ui.Signal()
				continue NextEvent
			}
			return nil
		}
	}
}

func (c *client) createAccountUI() {
	defaultServer := "pondserver://ICYUHSAYGIXTKYKXSAHIBWEAQCTEF26WUWEPOVC764WYELCJMUPA@jb644zapje5dvgk3.onion"
	if c.testing {
		defaultServer = "pondserver://ZGL2WALCGXCKYBIHTWL5Q3TPCOEHSQB2XON5JHA2KHM5PJ3C7AFA@127.0.0.1:16333"
	}

	ui := VBox{
		widgetBase: widgetBase{padding: 40, expand: true, fill: true, name: "vbox"},
		children: []Widget{
			Label{
				widgetBase: widgetBase{font: "DejaVu Sans 30"},
				text:       "Create Account",
			},
			Label{
				widgetBase: widgetBase{
					padding: 20,
					font:    "DejaVu Sans 14",
				},
				text: "In order to use Pond you have to have an account on a server. Servers may set their own account policies, but the default server allows anyone to create an account. If you want to use the default server, just click 'Create'.",
				wrap: 600,
			},
			HBox{
				spacing: 5,
				children: []Widget{
					Label{
						text:   "Server:",
						yAlign: 0.5,
					},
					Entry{
						widgetBase: widgetBase{name: "server"},
						width:      60,
						text:       defaultServer,
					},
				},
			},
			HBox{
				widgetBase: widgetBase{padding: 40},
				children: []Widget{
					Button{
						widgetBase: widgetBase{name: "create"},
						text:       "Create",
					},
				},
			},
		},
	}

	c.ui.Actions() <- SetBoxContents{name: "body", child: ui}
	c.ui.Actions() <- SetFocus{name: "create"}
	c.ui.Actions() <- UIState{uiStateCreateAccount}
	c.ui.Signal()

	var spinnerCreated bool
	for {
		click, ok := <-c.ui.Events()
		if !ok {
			c.ShutdownAndSuspend()
		}
		c.server = click.(Click).entries["server"]

		c.ui.Actions() <- Sensitive{name: "server", sensitive: false}
		c.ui.Actions() <- Sensitive{name: "create", sensitive: false}

		const initialMessage = "Checking..."

		if !spinnerCreated {
			c.ui.Actions() <- Append{
				name: "vbox",
				children: []Widget{
					HBox{
						widgetBase: widgetBase{name: "statusbox"},
						spacing:    10,
						children: []Widget{
							Spinner{
								widgetBase: widgetBase{name: "spinner"},
							},
							Label{
								widgetBase: widgetBase{name: "status"},
								text:       initialMessage,
							},
						},
					},
				},
			}
			spinnerCreated = true
		} else {
			c.ui.Actions() <- StartSpinner{name: "spinner"}
			c.ui.Actions() <- SetText{name: "status", text: initialMessage}
		}
		c.ui.Signal()

		if err := c.doCreateAccount(); err != nil {
			c.ui.Actions() <- StopSpinner{name: "spinner"}
			c.ui.Actions() <- UIError{err}
			c.ui.Actions() <- SetText{name: "status", text: err.Error()}
			c.ui.Actions() <- Sensitive{name: "server", sensitive: true}
			c.ui.Actions() <- Sensitive{name: "create", sensitive: true}
			c.ui.Signal()
			continue
		}

		break
	}
}

func (c *client) ShutdownAndSuspend() {
	if c.writerChan != nil {
		c.save()
	}
	c.Shutdown()
	close(c.ui.Actions())
	select {}
}

func (c *client) Shutdown() {
	close(c.pandaShutdownChan)
	if c.testing {
		c.pandaWaitGroup.Wait()

	ProcessPANDAUpdates:
		for {
			select {
			case update := <-c.pandaChan:
				c.processPANDAUpdate(update)
			default:
				break ProcessPANDAUpdates
			}
		}
	}
	if c.writerChan != nil {
		close(c.writerChan)
		<-c.writerDone
	}
	if c.fetchNowChan != nil {
		close(c.fetchNowChan)
	}
	if c.revocationUpdateChan != nil {
		close(c.revocationUpdateChan)
	}
	if c.stateLock != nil {
		c.stateLock.Close()
	}
}

// RunPANDA runs in its own goroutine and runs a PANDA key exchange.
func (c *client) runPANDA(serialisedKeyExchange []byte, id uint64, name string) {
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
		format = "Key exchange with " + name + ": " + format
		c.log.Printf(format, args...)
	}

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
		c.log.Printf("Key exchange with %s failed: %s", contact.name, update.err)
		c.contactsUI.SetSubline(contact.id, "failed")
	case update.serialised != nil:
		if bytes.Equal(contact.pandaKeyExchange, update.serialised) {
			return
		}
		contact.pandaKeyExchange = update.serialised
	case update.result != nil:
		if err := contact.processKeyExchange(update.result, c.testing); err != nil {
			contact.pandaResult = err.Error()
			c.contactsUI.SetSubline(contact.id, "failed")
			contact.pandaKeyExchange = nil
			c.log.Printf("Key exchange with %s failed: %s", contact.name, err)
		} else {
			c.unsealPendingMessages(contact)
			c.contactsUI.SetSubline(contact.id, "")
			contact.pandaKeyExchange = nil
			c.log.Printf("Key exchange with %s complete", contact.name)
			c.ui.Actions() <- UIState{uiStatePANDAComplete}
			c.ui.Signal()
		}
	}

	c.save()
}

// unsealPendingMessages is run once a key exchange with a contact has
// completed and unseals any previously unreadable messages from that contact.
func (c *client) unsealPendingMessages(contact *Contact) {
	contact.isPending = false

	for _, msg := range c.inbox {
		if msg.message == nil && msg.from == contact.id {
			if !c.unsealMessage(msg, contact) || len(msg.message.Body) == 0 {
				c.inboxUI.Remove(msg.id)
				continue
			}
			subline := time.Unix(*msg.message.Time, 0).Format(shortTimeFormat)
			c.inboxUI.SetSubline(msg.id, subline)
			c.inboxUI.SetIndicator(msg.id, indicatorBlue)
			c.updateWindowTitle()
		}
	}
}

type pandaUpdate struct {
	id         uint64
	err        error
	result     []byte
	serialised []byte
}

func NewClient(stateFilename string, ui UI, rand io.Reader, testing, autoFetch bool) *client {
	c := &client{
		testing:   testing,
		autoFetch: autoFetch,
		newMeetingPlace: func() panda.MeetingPlace {
			return &panda.HTTPMeetingPlace{
				URL: "https://panda-key-exchange.appspot.com/exchange",
			}
		},
		stateFilename:     stateFilename,
		log:               NewLog(),
		ui:                ui,
		rand:              rand,
		contacts:          make(map[uint64]*Contact),
		drafts:            make(map[uint64]*Draft),
		newMessageChan:    make(chan NewMessage),
		messageSentChan:   make(chan messageSendResult, 1),
		backgroundChan:    make(chan interface{}, 8),
		pandaChan:         make(chan pandaUpdate, 1),
		pandaShutdownChan: make(chan bool),
	}
	c.log.toStderr = true
	return c
}

func (c *client) Start() {
	go c.loadUI()
}
