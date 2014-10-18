// +build !nogui

package main

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/pond/client/disk"
	"github.com/agl/pond/panda"
	pond "github.com/agl/pond/protos"
)

const haveGUI = true

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
	colorImminently            = 0xffdddd
	colorDeleteSoon            = 0xdddddd
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
	uiStateRevocationComplete
	uiStatePANDAComplete
	uiStateErasureStorage
	uiStateTimerComplete
	uiStateEntomb
	uiStateEntombComplete
)

type guiClient struct {
	client

	gui                                               GUI
	inboxUI, outboxUI, contactsUI, clientUI, draftsUI *listUI
}

// nextEvent polls a number of event sources and returns a GUI event and a bool
// which indicates whether this is a global event or not. Global events are
// events like clicks on the lists on the left-hand-side, which cause the
// currently running interaction to be aborted.
//
// It takes the id of the currently active message (be it inbox or outbox),
// which can be zero if no message is currently being viewed. This id is used
// to prevent the deletion of those messages.
func (c *guiClient) nextEvent(currentMsgId uint64) (event interface{}, wanted bool) {
	var ok bool
	select {
	case sigReq := <-c.signingRequestChan:
		c.processSigningRequest(sigReq)
		return
	case event, ok = <-c.gui.Events():
		if !ok {
			c.ShutdownAndSuspend()
		}
	case newMessage := <-c.newMessageChan:
		c.processNewMessage(newMessage)
		return
	case msr := <-c.messageSentChan:
		if msr.id != 0 {
			c.processMessageSent(msr)
		}
		return
	case update := <-c.pandaChan:
		c.processPANDAUpdate(update)
		return
	case event = <-c.backgroundChan:
		break
	case <-c.log.updateChan:
		return
	case <-c.timerChan:
		c.processTimer(currentMsgId)
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

func (c *guiClient) processTimer(currentMsgId uint64) {
	now := c.Now()
	haveDeleted := false

RestartInboxIteration:
	for {
		for _, msg := range c.inbox {
			if msg.id != currentMsgId && !msg.retained && now.Sub(msg.receivedTime) > messageLifetime && now.Sub(msg.exposureTime) > messageGraceTime {
				if len(msg.message.Body) > 0 {
					c.inboxUI.Remove(msg.id)
				}
				c.deleteInboxMsg(msg.id)
				// c.inbox will have been updated by this
				// deletion so we start from the beginning
				// again.
				haveDeleted = true
				continue RestartInboxIteration
			}
			c.updateInboxBackgroundColor(msg)
		}
		break
	}

RestartOutboxIteration:
	for {
		for _, msg := range c.outbox {
			if msg.id != currentMsgId && now.Sub(msg.created) > messageLifetime {
				if msg.revocation || len(msg.message.Body) > 0 {
					c.outboxUI.Remove(msg.id)
				}
				c.deleteOutboxMsg(msg.id)
				haveDeleted = true
				continue RestartOutboxIteration
			}
		}
		break
	}

	if haveDeleted {
		c.save()
	}

	c.gui.Actions() <- UIState{uiStateTimerComplete}
	c.gui.Signal()
}

// torPromptUI displays a prompt to start Tor and tries once a second until it
// can be found.
func (c *guiClient) torPromptUI() error {
	ui := VBox{
		widgetBase: widgetBase{padding: 40, expand: true, fill: true, name: "vbox"},
		children: []Widget{
			Label{
				widgetBase: widgetBase{font: "DejaVu Sans 30"},
				text:       "Cannot find Tor",
			},
			Label{
				widgetBase: widgetBase{
					padding: 20,
					font:    "DejaVu Sans 14",
				},
				text: "Please start Tor or the Tor Browser Bundle. Looking for a SOCKS proxy on port 9050 or 9150...",
				wrap: 600,
			},
		},
	}

	c.gui.Actions() <- SetBoxContents{name: "body", child: ui}
	c.gui.Signal()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case _, ok := <-c.gui.Events():
			if !ok {
				c.ShutdownAndSuspend()
			}
		case <-ticker.C:
			if c.detectTor() {
				return nil
			}
		}
	}

	return nil
}

func (c *guiClient) sleepUI(d time.Duration) error {
	select {
	case _, ok := <-c.gui.Events():
		if !ok {
			// User asked to close the window.
			close(c.gui.Actions())
			select {}
		}
	case <-time.After(d):
		break
	}

	return nil
}

func (c *guiClient) initUI() {
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
	c.gui.Actions() <- Reset{ui}
}

func (c *guiClient) loadingUI() {
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

	c.gui.Actions() <- SetBoxContents{name: "body", child: loading}
	c.gui.Actions() <- UIState{uiStateLoading}
	c.gui.Signal()
}

func (c *guiClient) DeselectAll() {
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

func (c *guiClient) updateWindowTitle() {
	unreadCount := 0

	for _, msg := range c.inbox {
		if msg.message != nil && !msg.read && len(msg.message.Body) > 0 {
			unreadCount++
		}
	}

	if unreadCount == 0 {
		c.gui.Actions() <- SetTitle{"Pond"}
	} else {
		c.gui.Actions() <- SetTitle{fmt.Sprintf("Pond (%d)", unreadCount)}
	}
	c.gui.Signal()
}

func (c *guiClient) processFetch(inboxMsg *InboxMessage) {
	from := c.contacts[inboxMsg.from]

	if !from.isPending {
		if len(inboxMsg.message.Body) > 0 {
			subline := time.Unix(*inboxMsg.message.Time, 0).Format(shortTimeFormat)
			c.inboxUI.Add(inboxMsg.id, from.name, subline, indicatorBlue)
		}
	} else {
		c.inboxUI.Add(inboxMsg.id, from.name, "pending", indicatorRed)
	}

	c.updateWindowTitle()
}

func (c *guiClient) processServerAnnounce(inboxMsg *InboxMessage) {
	subline := time.Unix(*inboxMsg.message.Time, 0).Format(shortTimeFormat)
	c.inboxUI.Add(inboxMsg.id, c.ContactName(inboxMsg.from), subline, indicatorBlue)
	c.updateWindowTitle()
}

func (c *guiClient) processAcknowledgement(ackedMsg *queuedMessage) {
	c.outboxUI.SetIndicator(ackedMsg.id, indicatorGreen)
}

func (c *guiClient) processRevocationOfUs(by *Contact) {
	c.contactsUI.SetIndicator(by.id, indicatorBlack)
	c.contactsUI.SetSubline(by.id, "has revoked")

	c.queueMutex.Lock()
	for _, m := range c.queue {
		if m.to == by.id {
			c.outboxUI.SetIndicator(m.id, indicatorBlack)
		}
	}
	c.queueMutex.Unlock()
}

func (c *guiClient) processRevocation(by *Contact) {
	c.gui.Actions() <- UIState{uiStateRevocationProcessed}
	c.gui.Signal()
}

func (c *guiClient) processMessageDelivered(msg *queuedMessage) {
	c.outboxUI.SetIndicator(msg.id, indicatorYellow)
}

func (c *guiClient) mainUI() {
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

	c.gui.Actions() <- Reset{ui}
	c.gui.Signal()

	c.contactsUI = &listUI{
		gui:      c.gui,
		vboxName: "contactsVbox",
	}

	for id, contact := range c.contacts {
		c.contactsUI.Add(id, contact.name, contact.subline(), contact.indicator())
	}

	c.inboxUI = &listUI{
		gui:      c.gui,
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
		if msg.from != 0 {
			if i == indicatorNone && !msg.acked {
				i = indicatorYellow
			}
		}
		c.inboxUI.Add(msg.id, c.ContactName(msg.from), subline, i)
		c.updateInboxBackgroundColor(msg)
	}
	c.updateWindowTitle()

	c.outboxUI = &listUI{
		gui:      c.gui,
		vboxName: "outboxVbox",
	}

	for _, msg := range c.outbox {
		if msg.revocation {
			c.outboxUI.Add(msg.id, "Revocation", msg.created.Format(shortTimeFormat), msg.indicator(nil))
			c.outboxUI.SetInsensitive(msg.id)
			continue
		}
		if len(msg.message.Body) > 0 {
			subline := msg.created.Format(shortTimeFormat)
			c.outboxUI.Add(msg.id, c.ContactName(msg.to), subline, msg.indicator(c.contacts[msg.to]))
		}
	}

	c.draftsUI = &listUI{
		gui:      c.gui,
		vboxName: "draftsVbox",
	}

	for _, draft := range c.drafts {
		to := "Unknown"
		if draft.to != 0 {
			to = c.ContactName(draft.to)
		}
		subline := draft.created.Format(shortTimeFormat)
		c.draftsUI.Add(draft.id, to, subline, indicatorNone)
	}

	c.clientUI = &listUI{
		gui:      c.gui,
		vboxName: "clientVbox",
	}
	const (
		clientUIIdentity = iota + 1
		clientUIActivity
	)
	c.clientUI.Add(clientUIIdentity, "Identity", "", indicatorNone)
	c.clientUI.Add(clientUIActivity, "Activity Log", "", indicatorNone)

	c.gui.Actions() <- UIState{uiStateMain}
	c.gui.Signal()

	var nextEvent interface{}
	for {
		event := nextEvent
		nextEvent = nil
		if event == nil {
			event, _ = c.nextEvent(0)
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

// updateInboxBackgroundColor updates the background color of an inbox message
// in the listUI. For example, if a message is marked as "retain" then the
// background color may go from a warning indication to a normal color.
func (c *guiClient) updateInboxBackgroundColor(msg *InboxMessage) {
	now := c.Now()

	if !msg.retained {
		if now.Sub(msg.receivedTime) > messageLifetime {
			// The message will be deleted imminently.
			c.inboxUI.SetBackground(msg.id, colorImminently)
			return
		}
		if now.Sub(msg.receivedTime) > messagePreIndicationLifetime {
			// The message will be deleted soon.
			c.inboxUI.SetBackground(msg.id, colorDeleteSoon)
			return
		}
	}

	c.inboxUI.SetBackground(msg.id, colorGray)
}

func (c *guiClient) errorUI(errorText string, fatal bool) {
	bgColor := uint32(colorDefault)
	if fatal {
		bgColor = colorError
	}

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
	c.gui.Actions() <- SetBoxContents{name: "body", child: ui}
	c.gui.Actions() <- UIState{uiStateError}
	c.gui.Signal()
	if !c.testing {
		select {
		case _, ok := <-c.gui.Events():
			if !ok {
				// User asked to close the window.
				close(c.gui.Actions())
				select {}
			}
		}
	}
}

func (c *guiClient) keyPromptUI(stateFile *disk.StateFile) error {
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
				text: msgKeyPrompt,
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

	c.gui.Actions() <- SetBoxContents{name: "body", child: ui}
	c.gui.Actions() <- SetFocus{name: "pw"}
	c.gui.Actions() <- UIState{uiStatePassphrase}
	c.gui.Signal()

	for {
		event, ok := <-c.gui.Events()
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

		c.gui.Actions() <- Sensitive{name: "next", sensitive: false}
		c.gui.Actions() <- Sensitive{name: "pw", sensitive: false}
		c.gui.Signal()

		if err := c.loadState(stateFile, pw); err != disk.BadPasswordError {
			return err
		}

		c.gui.Actions() <- SetText{name: "status", text: msgIncorrectPassword}
		c.gui.Actions() <- SetEntry{name: "pw", text: ""}
		c.gui.Actions() <- Sensitive{name: "pw", sensitive: true}
		c.gui.Actions() <- SetFocus{name: "pw"}
		c.gui.Actions() <- Sensitive{name: "next", sensitive: true}
		c.gui.Signal()
	}

	return nil
}

func (c *guiClient) createPassphraseUI() (string, error) {
	ui := Grid{
		widgetBase: widgetBase{margin: 20},
		rowSpacing: 5,
		colSpacing: 5,
		rows: [][]GridE{
			{
				{2, 1, Label{
					widgetBase: widgetBase{font: "DejaVu Sans 30"},
					text:       "Set Passphrase",
				}},
			},
			{
				{2, 1, Label{
					widgetBase: widgetBase{
						padding: 20,
						font:    "DejaVu Sans 14",
					},
					text: msgCreatePassphrase,
					wrap: 600,
				}},
			},
			{
				{1, 1, Label{
					text:   "Passphrase:",
					yAlign: 0.5,
				}},
				{1, 1, Entry{
					widgetBase: widgetBase{name: "pw", hAlign: AlignStart, hExpand: true},
					width:      60,
					password:   true,
				}},
			},
			{
				{2, 1, Button{
					widgetBase: widgetBase{name: "next", hAlign: AlignStart},
					text:       "Next",
				}},
			},
		},
	}

	c.gui.Actions() <- SetBoxContents{name: "body", child: ui}
	c.gui.Actions() <- SetFocus{name: "pw"}
	c.gui.Actions() <- UIState{uiStateCreatePassphrase}
	c.gui.Signal()

	for {
		event, ok := <-c.gui.Events()
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

		return pw, nil
	}

	panic("unreachable")
}

func (c *guiClient) createAccountUI(stateFile *disk.StateFile, pw string) (didImport bool, err error) {
	defaultServer := msgDefaultServer
	if c.dev {
		defaultServer = msgDefaultDevServer
	}

	serverLabels := []string{"Default"}
	for _, server := range knownServers {
		serverLabels = append(serverLabels, server.description)
	}
	serverLabels = append(serverLabels, "Custom")

	ui := Grid{
		widgetBase: widgetBase{margin: 20},
		rowSpacing: 5,
		colSpacing: 5,
		rows: [][]GridE{
			{
				{2, 1, Label{
					widgetBase: widgetBase{font: "DejaVu Sans 30"},
					text:       "Create Account",
				}},
			},
			{
				{2, 1, Label{
					widgetBase: widgetBase{
						padding: 20,
						font:    "DejaVu Sans 14",
					},
					text: msgCreateAccount + " If you want to use the default server, just click 'Create'.",
					wrap: 600,
				}},
			},
			{
				{1, 1, Combo{
					widgetBase:  widgetBase{name: "servercombo"},
					labels:      serverLabels,
					preSelected: "Default",
				}},
				{1, 1, Entry{
					widgetBase: widgetBase{name: "server", hAlign: AlignStart, hExpand: true, margin: 10, insensitive: true},
					width:      60,
					text:       defaultServer,
				}},
			},
			{
				{2, 1, Button{
					widgetBase: widgetBase{name: "create", hAlign: AlignStart},
					text:       "Create",
				}},
			},
			{
				{2, 1, VBox{
					widgetBase: widgetBase{name: "vbox"},
				}},
			},
			{
				{2, 1, Grid{
					widgetBase: widgetBase{vAlign: AlignEnd, vExpand: true},
					rowSpacing: 5,
					colSpacing: 5,
					rows: [][]GridE{
						{
							{2, 1, Label{
								widgetBase: widgetBase{font: "bold"},
								text:       "Import entombed state file",
							}},
						},
						{
							{2, 1, Label{
								text: "Rather than creating a new account, it's also possible to import an 'entombed' state file. This is used when moving Pond from one computer to another.",
								wrap: 600,
							}},
						},
						{
							{1, 1, Label{
								text:   "Key:",
								yAlign: 0.5,
							}},
							{1, 1, Entry{
								widgetBase: widgetBase{name: "tombkey", hAlign: AlignStart, hExpand: true},
								width:      66,
							}},
						},
						{
							{1, 1, Button{
								widgetBase: widgetBase{name: "tombfile", hAlign: AlignStart},
								text:       "Select File",
							}},
							{1, 1, Button{
								widgetBase: widgetBase{name: "import", hAlign: AlignStart, insensitive: true},
								text:       "Import",
							}},
						},
						{
							{2, 1, Label{
								widgetBase: widgetBase{name: "tomberror", foreground: colorRed},
								wrap:       600,
							}},
						},
					},
				}},
			},
		},
	}

	c.gui.Actions() <- SetBoxContents{name: "body", child: ui}
	c.gui.Actions() <- SetFocus{name: "create"}
	c.gui.Actions() <- UIState{uiStateCreateAccount}
	c.gui.Signal()

	var spinnerCreated bool
	var tombPath string
	for {
		event, ok := <-c.gui.Events()
		if !ok {
			c.ShutdownAndSuspend()
		}

		if open, ok := event.(OpenResult); ok && open.ok {
			tombPath = open.path
			c.gui.Actions() <- Sensitive{name: "import", sensitive: true}
			c.gui.Signal()
			continue
		}

		click, ok := event.(Click)
		if !ok {
			continue
		}

		switch click.name {
		case "tombfile":
			c.gui.Actions() <- FileOpen{
				save:     false,
				title:    "Select path of entombed file",
				filename: "statefile.tomb",
				arg:      nil,
			}
			c.gui.Signal()
			continue
		case "import":
			if err := c.importTombFile(stateFile, click.entries["tombkey"], tombPath); err == nil {
				err = c.loadState(stateFile, pw)
			}
			if err != nil {
				c.gui.Actions() <- SetText{name: "tomberror", text: err.Error()}
				c.gui.Actions() <- UIError{err}
				c.gui.Signal()
				continue
			}

			c.lastErasureStorageTime = time.Now()
			return true, nil
		case "servercombo":
			selected := click.combos["servercombo"]
			server := ""

			switch selected {
			case "Default":
				server = defaultServer
			case "Custom":
				server = ""
			default:
				for _, known := range knownServers {
					if known.description == selected {
						server = known.uri
					}
				}
			}

			c.gui.Actions() <- Sensitive{name: "server", sensitive: len(server) == 0}
			c.gui.Actions() <- SetEntry{name: "server", text: server}
			c.gui.Signal()
			continue
		case "create":
			break
		default:
			continue
		}

		c.server = click.entries["server"]

		c.gui.Actions() <- Sensitive{name: "server", sensitive: false}
		c.gui.Actions() <- Sensitive{name: "create", sensitive: false}

		const initialMessage = "Checking..."

		if !spinnerCreated {
			c.gui.Actions() <- SetBoxContents{
				name: "vbox",
				child: HBox{
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
			}
			spinnerCreated = true
		} else {
			c.gui.Actions() <- StartSpinner{name: "spinner"}
			c.gui.Actions() <- SetText{name: "status", text: initialMessage}
		}
		c.gui.Signal()

		updateMsg := func(msg string) {
			c.gui.Actions() <- SetText{name: "status", text: msg}
			c.gui.Signal()
		}

		if err := c.doCreateAccount(updateMsg); err != nil {
			c.gui.Actions() <- StopSpinner{name: "spinner"}
			c.gui.Actions() <- UIError{err}
			c.gui.Actions() <- SetText{name: "status", text: err.Error()}
			c.gui.Actions() <- Sensitive{name: "server", sensitive: true}
			c.gui.Actions() <- Sensitive{name: "create", sensitive: true}
			c.gui.Signal()
			continue
		}

		break
	}

	return false, nil
}

func (c *guiClient) ShutdownAndSuspend() error {
	if c.writerChan != nil {
		c.save()
	}
	c.Shutdown()
	close(c.gui.Actions())
	select {}
	return nil
}

func (c *guiClient) Shutdown() {
	for _, contact := range c.contacts {
		if contact.pandaShutdownChan != nil {
			close(contact.pandaShutdownChan)
		}
	}
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
	if c.stateLock != nil {
		c.stateLock.Close()
	}
}

type InboxDetachmentUI struct {
	msg *InboxMessage
	gui GUI
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
	i.gui.Actions() <- Sensitive{
		name:      fmt.Sprintf("detachment-decrypt-%d", i.msg.decryptions[id].index),
		sensitive: true,
	}
	i.gui.Actions() <- Sensitive{
		name:      fmt.Sprintf("detachment-download-%d", i.msg.decryptions[id].index),
		sensitive: true,
	}
	delete(i.msg.decryptions, id)
}

func (i InboxDetachmentUI) OnSuccess(id uint64, detachment *pond.Message_Detachment) {
}
func (c *guiClient) showInbox(id uint64) interface{} {
	var msg *InboxMessage
	for _, candidate := range c.inbox {
		if candidate.id == id {
			msg = candidate
			break
		}
	}
	if msg == nil {
		panic("failed to find message in inbox")
	}
	isServerAnnounce := msg.from == 0
	isPending := msg.message == nil
	if msg.message != nil && !msg.read {
		msg.read = true
		i := indicatorYellow
		if isServerAnnounce {
			i = indicatorNone
		}
		c.inboxUI.SetIndicator(id, i)
		c.updateWindowTitle()
		c.save()
	}

	sentTimeText, eraseTimeText, msgText := msg.Strings()

	left := Grid{
		widgetBase: widgetBase{margin: 6, name: "lhs"},
		rowSpacing: 3,
		colSpacing: 3,
		rows: [][]GridE{
			{
				{1, 1, Label{
					widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, hAlign: AlignEnd, vAlign: AlignCenter},
					text:       "FROM",
				}},
				// We set hExpand true here so that the
				// attachments/detachments UI doesn't cause the
				// first column to expand.
				{1, 1, Label{widgetBase: widgetBase{hExpand: true}, text: c.ContactName(msg.from)}},
			},
			{
				{1, 1, Label{
					widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, hAlign: AlignEnd, vAlign: AlignCenter},
					text:       "SENT",
				}},
				{1, 1, Label{text: sentTimeText}},
			},
			{
				{1, 1, Label{
					widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, hAlign: AlignEnd, vAlign: AlignCenter},
					text:       "ERASE",
				}},
				{1, 1, Label{text: eraseTimeText}},
			},
		},
	}
	lhsNextRow := len(left.rows)

	right := Grid{
		widgetBase: widgetBase{margin: 6},
		rowSpacing: 3,
		colSpacing: 3,
		rows: [][]GridE{
			{
				{1, 1, Button{
					widgetBase: widgetBase{
						name:        "reply",
						insensitive: isServerAnnounce || isPending,
					},
					text: "Reply",
				}},
			},
			{
				{1, 1, Button{
					widgetBase: widgetBase{
						name:        "ack",
						insensitive: isServerAnnounce || isPending || msg.acked,
					},
					text: "Ack",
				}},
			},
			{
				{1, 1, Button{
					widgetBase: widgetBase{
						name: "delete",
					},
					text: "Delete Now",
				}},
			},
			{
				{1, 1, CheckButton{
					widgetBase: widgetBase{
						name: "retain",
					},
					checked: msg.retained,
					text:    "Retain",
				}},
			},
		},
	}

	main := TextView{
		widgetBase: widgetBase{hExpand: true, vExpand: true, name: "body"},
		editable:   false,
		text:       msgText,
		wrap:       true,
	}

	c.gui.Actions() <- SetChild{name: "right", child: rightPane("RECEIVED MESSAGE", left, right, main)}

	// The UI names widgets with strings so these prefixes are used to
	// generate names for the dynamic parts of the UI.
	const (
		detachmentDecryptPrefix  = "detachment-decrypt-"
		detachmentVBoxPrefix     = "detachment-decrypt-"
		detachmentProgressPrefix = "detachment-progress-"
		detachmentDownloadPrefix = "detachment-download-"
		detachmentSavePrefix     = "detachment-save-"
		attachmentPrefix         = "attachment-"
	)

	widgetForDetachmentProcess := func(index int) Widget {
		return VBox{
			widgetBase: widgetBase{name: fmt.Sprintf("detachment-vbox-%d", index)},
			children: []Widget{
				Progress{
					widgetBase: widgetBase{
						name: fmt.Sprintf("%s%d", detachmentProgressPrefix, index),
					},
				},
			},
		}
	}

	if msg.message != nil && len(msg.message.Files) != 0 {
		grid := Grid{widgetBase: widgetBase{marginLeft: 25}, rowSpacing: 3}

		for i, attachment := range msg.message.Files {
			filename := maybeTruncate(*attachment.Filename)
			grid.rows = append(grid.rows, []GridE{
				{1, 1, Label{
					widgetBase: widgetBase{vAlign: AlignCenter, hAlign: AlignStart},
					text:       filename,
				}},
				{1, 1, Button{
					widgetBase: widgetBase{name: fmt.Sprintf("%s%d", attachmentPrefix, i)},
					text:       "Save",
				}},
			})
		}

		c.gui.Actions() <- InsertRow{name: "lhs", pos: lhsNextRow, row: []GridE{
			{1, 1, Label{
				widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, hAlign: AlignEnd, vAlign: AlignCenter},
				text:       "ATTACHMENTS",
			}},
		}}
		lhsNextRow++
		c.gui.Actions() <- InsertRow{name: "lhs", pos: lhsNextRow, row: []GridE{{2, 1, grid}}}
		lhsNextRow++
	}

	if msg.message != nil && len(msg.message.DetachedFiles) != 0 {
		grid := Grid{widgetBase: widgetBase{name: "detachment-grid", marginLeft: 25}, rowSpacing: 3}

		for i, detachment := range msg.message.DetachedFiles {
			filename := maybeTruncate(*detachment.Filename)
			var pending *pendingDecryption
			for _, candidate := range msg.decryptions {
				if candidate.index == i {
					pending = candidate
					break
				}
			}
			row := []GridE{
				{1, 1, Label{
					widgetBase: widgetBase{vAlign: AlignCenter, hAlign: AlignStart},
					text:       filename,
				}},
				{1, 1, Button{
					widgetBase: widgetBase{
						name:        fmt.Sprintf("%s%d", detachmentDecryptPrefix, i),
						padding:     3,
						insensitive: pending != nil,
					},
					text: "Decrypt local file with key",
				}},
				{1, 1, Button{
					widgetBase: widgetBase{
						name:    fmt.Sprintf("%s%d", detachmentSavePrefix, i),
						padding: 3,
					},
					text: "Save key to disk",
				}},
			}
			if detachment.Url != nil && len(*detachment.Url) > 0 {
				row = append(row, GridE{1, 1,
					Button{
						widgetBase: widgetBase{
							name:        fmt.Sprintf("%s%d", detachmentDownloadPrefix, i),
							padding:     3,
							insensitive: pending != nil,
						},
						text: "Download",
					},
				})
			}
			var progressRow []GridE
			if pending != nil {
				progressRow = append(progressRow, GridE{4, 1, widgetForDetachmentProcess(i)})
			}
			grid.rows = append(grid.rows, row)
			grid.rows = append(grid.rows, progressRow)
		}

		c.gui.Actions() <- InsertRow{name: "lhs", pos: lhsNextRow, row: []GridE{
			{1, 1, Label{
				widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, hAlign: AlignEnd, vAlign: AlignCenter},
				text:       "KEYS",
			}},
		}}
		lhsNextRow++
		c.gui.Actions() <- InsertRow{name: "lhs", pos: lhsNextRow, row: []GridE{{2, 1, grid}}}
		lhsNextRow++
		c.gui.Signal()
	}

	c.gui.Actions() <- UIState{uiStateInbox}
	c.gui.Signal()

	detachmentUI := InboxDetachmentUI{msg, c.gui}

	if msg.decryptions == nil {
		msg.decryptions = make(map[uint64]*pendingDecryption)
	}

NextEvent:
	for {
		event, wanted := c.nextEvent(msg.id)
		if wanted {
			return event
		}

		// These types are returned by the UI from a file dialog and
		// serve to identify the actions that should be taken with the
		// resulting filename.
		type (
			attachmentSaveIndex    int
			detachmentSaveIndex    int
			detachmentDecryptIndex int
			detachmentDecryptInput struct {
				index  int
				inPath string
			}
			detachmentDownloadIndex int
		)

		if open, ok := event.(OpenResult); ok && open.ok {
			switch i := open.arg.(type) {
			case attachmentSaveIndex:
				// Save an attachment to disk.
				ioutil.WriteFile(open.path, msg.message.Files[i].Contents, 0600)
			case detachmentSaveIndex:
				// Save a detachment key to disk.
				bytes, err := proto.Marshal(msg.message.DetachedFiles[i])
				if err != nil {
					panic(err)
				}
				ioutil.WriteFile(open.path, bytes, 0600)
			case detachmentDecryptIndex:
				// Decrypt a local file with a detachment key.
				c.gui.Actions() <- FileOpen{
					save:     true,
					title:    "Save decrypted file",
					filename: filepath.Base(open.path),
					arg: detachmentDecryptInput{
						index:  int(i),
						inPath: open.path,
					},
				}
				c.gui.Signal()
			case detachmentDecryptInput:
				// Decrypt a local file with a detachment key,
				// after the second save dialog - which prompts
				// for where to write the new key.
				for _, decryption := range msg.decryptions {
					if decryption.index == i.index {
						continue NextEvent
					}
				}
				c.gui.Actions() <- Sensitive{
					name:      fmt.Sprintf("%s%d", detachmentDecryptPrefix, i.index),
					sensitive: false,
				}
				c.gui.Actions() <- Sensitive{
					name:      fmt.Sprintf("%s%d", detachmentDownloadPrefix, i.index),
					sensitive: false,
				}
				c.gui.Actions() <- InsertRow{
					name: "detachment-grid",
					pos:  i.index*2 + 1,
					row:  []GridE{{4, 1, widgetForDetachmentProcess(i.index)}},
				}
				id := c.randId()
				msg.decryptions[id] = &pendingDecryption{
					index:  i.index,
					cancel: c.startDecryption(id, open.path, i.inPath, msg.message.DetachedFiles[i.index]),
				}
				c.gui.Signal()
			case detachmentDownloadIndex:
				// Download a detachment.
				for _, decryption := range msg.decryptions {
					if decryption.index == int(i) {
						continue NextEvent
					}
				}
				c.gui.Actions() <- Sensitive{
					name:      fmt.Sprintf("%s%d", detachmentDecryptPrefix, i),
					sensitive: false,
				}
				c.gui.Actions() <- Sensitive{
					name:      fmt.Sprintf("%s%d", detachmentDownloadPrefix, i),
					sensitive: false,
				}
				c.gui.Actions() <- InsertRow{
					name: "detachment-grid",
					pos:  int(i)*2 + 1,
					row:  []GridE{{4, 1, widgetForDetachmentProcess(int(i))}},
				}
				id := c.randId()
				msg.decryptions[id] = &pendingDecryption{
					index:  int(i),
					cancel: c.startDownload(id, open.path, msg.message.DetachedFiles[i]),
				}
				c.gui.Signal()
			default:
				panic("unimplemented OpenResult")
			}
			continue
		}

		if c.maybeProcessDetachmentMsg(event, detachmentUI) {
			continue
		}

		click, ok := event.(Click)
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(click.name, attachmentPrefix):
			i, _ := strconv.Atoi(click.name[len(attachmentPrefix):])
			c.gui.Actions() <- FileOpen{
				save:     true,
				title:    "Save Attachment",
				filename: msg.message.Files[i].GetFilename(),
				arg:      attachmentSaveIndex(i),
			}
			c.gui.Signal()
			continue
		case strings.HasPrefix(click.name, detachmentSavePrefix):
			i, _ := strconv.Atoi(click.name[len(detachmentSavePrefix):])
			c.gui.Actions() <- FileOpen{
				save:     true,
				title:    "Save Key",
				filename: msg.message.DetachedFiles[i].GetFilename() + ".key",
				arg:      detachmentSaveIndex(i),
			}
			c.gui.Signal()
			continue
		case strings.HasPrefix(click.name, detachmentDecryptPrefix):
			i, _ := strconv.Atoi(click.name[len(detachmentDecryptPrefix):])
			c.gui.Actions() <- FileOpen{
				title: "Select encrypted file",
				arg:   detachmentDecryptIndex(i),
			}
			c.gui.Signal()
			continue
		case strings.HasPrefix(click.name, detachmentDownloadPrefix):
			i, _ := strconv.Atoi(click.name[len(detachmentDownloadPrefix):])
			c.gui.Actions() <- FileOpen{
				save:     true,
				title:    "Save to",
				filename: msg.message.DetachedFiles[i].GetFilename(),
				arg:      detachmentDownloadIndex(i),
			}
			c.gui.Signal()
			continue
		case click.name == "ack":
			c.gui.Actions() <- Sensitive{name: "ack", sensitive: false}
			c.gui.Signal()
			msg.acked = true
			c.sendAck(msg)
			c.inboxUI.SetIndicator(msg.id, indicatorNone)
			c.gui.Actions() <- UIState{uiStateInbox}
			c.gui.Signal()
		case click.name == "reply":
			c.inboxUI.Deselect()
			return c.composeUI(nil, msg)
		case click.name == "delete":
			c.inboxUI.Remove(msg.id)
			c.deleteInboxMsg(msg.id)
			c.gui.Actions() <- SetChild{name: "right", child: rightPlaceholderUI}
			c.gui.Actions() <- UIState{uiStateMain}
			c.gui.Signal()
			c.save()
			return nil
		case click.name == "retain":
			msg.retained = click.checks["retain"]
			if !msg.retained {
				msg.exposureTime = c.Now()
			}
			c.updateInboxBackgroundColor(msg)
			c.save()
			c.gui.Actions() <- UIState{uiStateInbox}
			c.gui.Signal()
		}
	}

	return nil
}

func (c *guiClient) showOutbox(id uint64) interface{} {
	var msg *queuedMessage
	for _, candidate := range c.outbox {
		if candidate.id == id {
			msg = candidate
			break
		}
	}
	if msg == nil {
		panic("failed to find message in outbox")
	}

	contact := c.contacts[msg.to]
	var sentTime string
	if contact.revokedUs {
		sentTime = "(never - contact has revoked us)"
	} else {
		sentTime = formatTime(msg.sent)
	}
	eraseTime := formatTime(msg.created.Add(messageLifetime))

	canAbort := !contact.revokedUs && msg.sent.IsZero()
	if canAbort {
		c.queueMutex.Lock()
		if msg.sending {
			canAbort = false
		}
		c.queueMutex.Unlock()
	}

	left := Grid{
		widgetBase: widgetBase{margin: 6},
		rowSpacing: 3,
		colSpacing: 3,
		rows: [][]GridE{
			{
				{1, 1, Label{
					widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, hAlign: AlignEnd, vAlign: AlignCenter},
					text:       "TO",
				}},
				{1, 1, Label{text: contact.name}},
			},
			{
				{1, 1, Label{
					widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, hAlign: AlignEnd, vAlign: AlignCenter},
					text:       "CREATED",
				}},
				{1, 1, Label{
					text: time.Unix(*msg.message.Time, 0).Format(time.RFC1123),
				}},
			},
			{
				{1, 1, Label{
					widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, hAlign: AlignEnd, vAlign: AlignCenter},
					text:       "SENT",
				}},
				{1, 1, Label{
					widgetBase: widgetBase{name: "sent"},
					text:       sentTime,
				}},
			},
			{
				{1, 1, Label{
					widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, hAlign: AlignEnd, vAlign: AlignCenter},
					text:       "ACKNOWLEDGED",
				}},
				{1, 1, Label{
					widgetBase: widgetBase{name: "acked"},
					text:       formatTime(msg.acked),
				}},
			},
			{
				{1, 1, Label{
					widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, hAlign: AlignEnd, vAlign: AlignCenter},
					text:       "ERASE",
				}},
				{1, 1, Label{
					text: eraseTime,
				}},
			},
		},
	}

	right := Grid{
		widgetBase: widgetBase{margin: 6},
		rowSpacing: 3,
		colSpacing: 3,
		rows: [][]GridE{
			{
				{1, 1, Button{
					widgetBase: widgetBase{
						name:        "abort",
						insensitive: !canAbort,
					},
					text: "Abort Send",
				}},
			},
			{
				{1, 1, Button{
					widgetBase: widgetBase{
						name:        "delete",
						insensitive: canAbort,
					},
					text: "Delete",
				}},
			},
		},
	}

	main := TextView{
		widgetBase: widgetBase{vExpand: true, hExpand: true, name: "body"},
		editable:   false,
		text:       string(msg.message.Body),
		wrap:       true,
	}

	c.gui.Actions() <- SetChild{name: "right", child: rightPane("SENT MESSAGE", left, right, main)}
	c.gui.Actions() <- UIState{uiStateOutbox}
	c.gui.Signal()

	haveSentTime := !msg.sent.IsZero()
	haveAckTime := !msg.acked.IsZero()

	for {
		event, wanted := c.nextEvent(msg.id)
		if wanted {
			return event
		}

		if click, ok := event.(Click); ok && click.name == "abort" {
			c.queueMutex.Lock()
			indexOfMessage := c.indexOfQueuedMessage(msg)
			if indexOfMessage == -1 || msg.sending {
				// Sorry - too late. Can't abort now.
				c.queueMutex.Unlock()

				canAbort = false
				c.gui.Actions() <- Sensitive{name: "abort", sensitive: canAbort}
				c.gui.Actions() <- Sensitive{name: "delete", sensitive: !canAbort}
				c.gui.Signal()
				continue
			}

			c.removeQueuedMessage(indexOfMessage)
			c.queueMutex.Unlock()

			c.deleteOutboxMsg(msg.id)
			c.outboxUI.Remove(msg.id)

			draft := c.outboxToDraft(msg)
			c.draftsUI.Add(draft.id, c.ContactName(msg.to), draft.created.Format(shortTimeFormat), indicatorNone)
			c.draftsUI.Select(draft.id)
			c.drafts[draft.id] = draft
			c.save()
			return c.composeUI(draft, nil)
		}

		if click, ok := event.(Click); ok && click.name == "delete" {
			c.deleteOutboxMsg(msg.id)
			// Also find and delete any empty acks for this message.
			for _, inboxMsg := range c.inbox {
				if inboxMsg.message != nil && len(inboxMsg.message.Body) == 0 && inboxMsg.message.InReplyTo != nil && *inboxMsg.message.InReplyTo == msg.id {
					c.deleteInboxMsg(inboxMsg.id)
					break
				}
			}
			c.save()
			if msg.revocation || len(msg.message.Body) > 0 {
				c.outboxUI.Remove(msg.id)
			}
			c.gui.Actions() <- SetChild{name: "right", child: rightPlaceholderUI}
			c.gui.Actions() <- UIState{uiStateMain}
			c.gui.Signal()
			return nil
		}

		if !haveSentTime && !msg.sent.IsZero() {
			c.gui.Actions() <- SetText{name: "sent", text: formatTime(msg.sent)}
			c.gui.Signal()
		}
		if !haveAckTime && !msg.acked.IsZero() {
			c.gui.Actions() <- SetText{name: "acked", text: formatTime(msg.acked)}
			c.gui.Signal()
		}

		canAbortChanged := false
		c.queueMutex.Lock()
		if c := !contact.revokedUs && msg.sent.IsZero() && !msg.sending; c != canAbort {
			canAbort = c
			canAbortChanged = true
		}
		c.queueMutex.Unlock()

		if canAbortChanged {
			c.gui.Actions() <- Sensitive{name: "abort", sensitive: canAbort}
			c.gui.Actions() <- Sensitive{name: "delete", sensitive: !canAbort}
			c.gui.Signal()
		}
	}

	return nil
}

func rightPane(title string, left, right, main Widget) Grid {
	var mid []GridE
	if left != nil {
		mid = append(mid, GridE{1, 1, left})
	}
	mid = append(mid, GridE{1, 1, Label{widgetBase: widgetBase{hExpand: true}}})
	if right != nil {
		mid = append(mid, GridE{1, 1, right})
	}

	grid := Grid{
		rows: [][]GridE{
			{
				{3, 1, EventBox{
					widgetBase: widgetBase{background: colorHeaderBackground, hExpand: true},
					child: Label{
						widgetBase: widgetBase{font: fontMainTitle, margin: 10, foreground: colorHeaderForeground, hExpand: true},
						text:       title,
					},
				}},
			},
			{
				{3, 1, EventBox{widgetBase: widgetBase{height: 1, background: colorSep}}},
			},
			mid,
			{},
		},
	}

	if main != nil {
		grid.rows = append(grid.rows, []GridE{{3, 1, main}})
	}

	return grid
}

type nvEntry struct {
	name, value string
}

func nameValuesLHS(entries []nvEntry) Widget {
	grid := Grid{
		widgetBase: widgetBase{margin: 6, name: "lhs"},
		rowSpacing: 3,
		colSpacing: 3,
	}
	for _, ent := range entries {
		var font string
		vAlign := AlignCenter
		if strings.HasPrefix(ent.value, "-----") {
			// PEM block
			font = fontMainMono
			vAlign = AlignStart
		}

		grid.rows = append(grid.rows, []GridE{
			GridE{1, 1, Label{
				widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, hAlign: AlignEnd, vAlign: vAlign},
				text:       ent.name,
			}},
			GridE{1, 1, Label{
				widgetBase: widgetBase{font: font},
				text:       ent.value,
				selectable: true,
			}},
		})
	}

	return grid
}

func (c *guiClient) identityUI() interface{} {
	entries := nameValuesLHS([]nvEntry{
		{"SERVER", c.server},
		{"PUBLIC IDENTITY", fmt.Sprintf("%x", c.identityPublic[:])},
		{"PUBLIC KEY", fmt.Sprintf("%x", c.pub[:])},
		{"STATE FILE", c.stateFilename},
		{"GROUP GENERATION", fmt.Sprintf("%d", c.generation)},
	})

	left := Grid{
		widgetBase: widgetBase{margin: 6},
		rowSpacing: 10,
		colSpacing: 3,
		rows: [][]GridE{
			{
				{1, 1, entries},
			},
			{
				{1, 1, Grid{
					widgetBase: widgetBase{margin: 6},
					rowSpacing: 3,
					colSpacing: 3,
					rows: [][]GridE{
						{
							{3, 1, Label{
								widgetBase: widgetBase{
									font: "bold",
								},
								text: "Entombing",
							}},
						},
						{
							{3, 1, Label{
								text: "Entombing your statefile causes it to be converted into an encrypted file that can be moved to a different computer. The file is encrypted with an ephemeral key that is printed at the end of the entombing process and must be written down. The original statefile is erased. Once the entombed file has been imported elsewhere, the paper with the ephemeral key must be destroyed.",
								wrap: 600,
							}},
						},
						{
							{1, 1, Button{
								widgetBase: widgetBase{name: "tombfile"},
								text:       "Select file",
							}},
							{1, 1, Button{
								widgetBase: widgetBase{
									name:        "entomb",
									insensitive: true,
								},
								text: "Entomb",
							}},
							{1, 1, Label{
								widgetBase: widgetBase{hExpand: true},
							}},
						},
						{
							{3, 1, Label{
								widgetBase: widgetBase{
									name:       "tomberror",
									foreground: colorRed,
								},
							}},
						},
					},
				}},
			},
		},
	}

	c.gui.Actions() <- SetChild{name: "right", child: rightPane("IDENTITY", left, nil, nil)}
	c.gui.Actions() <- UIState{uiStateShowIdentity}
	c.gui.Signal()

	var tombPath string

	for {
		event, wanted := c.nextEvent(0)
		if wanted {
			return event
		}

		if open, ok := event.(OpenResult); ok && open.ok {
			tombPath = open.path
			c.gui.Actions() <- Sensitive{name: "entomb", sensitive: true}
			c.gui.Signal()
			continue
		}

		click, ok := event.(Click)
		if !ok {
			continue
		}

		switch click.name {
		case "tombfile":
			c.gui.Actions() <- FileOpen{
				save:     true,
				title:    "Select path for entombed file",
				filename: "statefile.tomb",
				arg:      nil,
			}
			c.gui.Signal()
		case "entomb":
			f, err := os.OpenFile(tombPath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0400)
			if err != nil {
				c.gui.Actions() <- SetText{
					name: "tomberror",
					text: err.Error(),
				}
				c.gui.Actions() <- UIError{err}
				c.gui.Signal()
				continue
			}

			c.gui.Actions() <- Reset{TextView{
				widgetBase: widgetBase{name: "log"},
				editable:   false,
				wrap:       true,
			}}
			c.gui.Actions() <- UIState{uiStateEntomb}
			c.gui.Signal()

			var logText string
			log := func(msg string, args ...interface{}) {
				logText += fmt.Sprintf(msg, args...)
				c.gui.Actions() <- SetTextView{
					name: "log",
					text: logText,
				}
				c.gui.Signal()
			}

			key, ok := c.entomb(tombPath, f, log)
			if ok {
				log("\nThe process has completed successfully. You must write down the ephemeral key now. You can close this window when done.\n")
				c.gui.Actions() <- UIInfo{fmt.Sprintf("%x", key[:])}
			} else {
				log("\nThe process failed! Your statefile is still intact. Please close this window and restart when ready.")
			}

			c.gui.Actions() <- UIState{uiStateEntombComplete}
			c.gui.Signal()

			for {
				if _, ok := <-c.gui.Events(); !ok {
					break
				}
			}
			close(c.gui.Actions())
			select {}
		}
	}

	panic("unreachable")
}

func (c *guiClient) showContact(id uint64) interface{} {
	contact := c.contacts[id]
	if contact.isPending && len(contact.pandaKeyExchange) == 0 && len(contact.pandaResult) == 0 {
		return c.newContactUI(contact)
	}
	c.contactsUI.SetIndicator(id, indicatorNone)

	entries := []nvEntry{
		{"NAME", contact.name},
		{"SERVER", contact.theirServer},
		{"PUBLIC IDENTITY", fmt.Sprintf("%x", contact.theirIdentityPublic[:])},
		{"PUBLIC KEY", fmt.Sprintf("%x", contact.theirPub[:])},
		{"LAST DH", fmt.Sprintf("%x", contact.theirLastDHPublic[:])},
		{"CURRENT DH", fmt.Sprintf("%x", contact.theirCurrentDHPublic[:])},
		{"GROUP GENERATION", fmt.Sprintf("%d", contact.generation)},
		{"CLIENT VERSION", fmt.Sprintf("%d", contact.supportedVersion)},
	}

	var pandaMessage string

	if len(contact.pandaResult) > 0 {
		pandaMessage = contact.pandaResult
	} else if len(contact.pandaKeyExchange) > 0 {
		pandaMessage = "in progress"
	}

	if len(pandaMessage) > 0 {
		entries = append(entries, nvEntry{"PANDA KEY EXCHANGE", pandaMessage})
	} else if len(contact.kxsBytes) > 0 {
		var out bytes.Buffer
		pem.Encode(&out, &pem.Block{Bytes: contact.kxsBytes, Type: keyExchangePEM})
		entries = append(entries, nvEntry{"KEY EXCHANGE", string(out.Bytes())})
	}

	if len(contact.events) > 0 {
		eventsText := ""
		for i, event := range contact.events {
			if i > 0 {
				eventsText += "\n"
			}
			eventsText += event.t.Format(logTimeFormat)
			eventsText += ": "
			eventsText += event.msg
		}
		entries = append(entries, nvEntry{"EVENTS", eventsText})
	}

	right := Grid{
		widgetBase: widgetBase{margin: 6},
		rowSpacing: 3,
		colSpacing: 3,
		rows: [][]GridE{
			{
				{1, 1, Button{
					widgetBase: widgetBase{
						name: "delete",
					},
					text: "Delete",
				}},
			},
		},
	}

	left := nameValuesLHS(entries)
	c.gui.Actions() <- SetChild{name: "right", child: rightPane("CONTACT", left, right, nil)}
	c.gui.Actions() <- UIState{uiStateShowContact}
	c.gui.Signal()

	deleteArmed := false

	for {
		event, wanted := c.nextEvent(0)
		if wanted {
			return event
		}

		click, ok := event.(Click)
		if !ok {
			continue
		}

		if click.name == "delete" {
			if deleteArmed {
				c.gui.Actions() <- Sensitive{name: "delete", sensitive: false}
				c.gui.Signal()
				c.deleteContact(contact)
				c.gui.Actions() <- SetChild{name: "right", child: rightPlaceholderUI}
				c.gui.Actions() <- UIState{uiStateRevocationComplete}
				c.gui.Signal()
				c.save()
				return nil
			} else {
				deleteArmed = true
				c.gui.Actions() <- SetButtonText{name: "delete", text: "Confirm"}
				c.gui.Signal()
			}
		}
	}

	panic("unreachable")
}

func (c *guiClient) newContactUI(contact *Contact) interface{} {
	var name string
	existing := contact != nil
	if existing {
		name = contact.name
	}

	grid := Grid{
		widgetBase: widgetBase{name: "grid", margin: 5},
		rowSpacing: 8,
		colSpacing: 3,
		rows: [][]GridE{
			{
				{1, 1, Label{text: "1."}},
				{1, 1, Label{text: "Choose a name for this contact."}},
			},
			{
				{1, 1, nil},
				{1, 1, Label{text: "You can choose any name for this contact. It will be used to identify the contact to you and must be unique amongst all your contacts. However, it will not be revealed to anyone else nor used automatically in messages.", wrap: 400}},
			},
			{
				{1, 1, nil},
				{1, 1, Entry{
					widgetBase: widgetBase{name: "name", insensitive: existing},
					width:      20,
					text:       name,
				}},
			},
			{
				{1, 1, nil},
				{1, 1, Label{
					widgetBase: widgetBase{name: "error1", foreground: colorRed},
				}},
			},
			{
				{1, 1, Label{text: "2."}},
				{1, 1, Label{text: "Choose a key agreement method."}},
			},
			{
				{1, 1, nil},
				{1, 1, Label{text: `Shared secret keying involves anonymously contacting a global, shared service and performing key agreement with another party who holds the same shared secret.

If the other party is someone who you are in email or IM contact with, then a button is provided to generate a secret, which can then be sent to the other party. Neither Email nor IM ensures that someone didn't change the secret during transmission but you can verify the other party's fingerprint later and, as always, have to weigh convenience against security.

If, for example, you met your contact in real life, you could agree on a shared secret and the time (to the minute). Later you can both use this function to bootstrap Pond communication. The security of this scheme rests on the secret being unguessable, which is very hard for humans to manage. So there is also a scheme whereby a deck of cards can be shuffled and split between you.

Manual keying (not generally recommended) involves exchanging key material with your contact in a secure and authentic manner, i.e. by using PGP. The security of Pond is moot if you actually exchange keys with an attacker: they can masquerade the intended contact or could simply do the same to them and pass messages between you, reading everything in the process. Note that the key material is also secret - it's not a public key and so must be encrypted as well as signed.`, wrap: 400}},
			},
			{
				{1, 1, nil},
				{1, 1, Grid{
					widgetBase: widgetBase{marginTop: 20},
					rows: [][]GridE{
						{
							{1, 1, Label{widgetBase: widgetBase{hExpand: true}}},
							{1, 1, Button{
								widgetBase: widgetBase{
									name: "shared",
								},
								text: "Shared secret",
							}},
							{1, 1, Label{widgetBase: widgetBase{hExpand: true}}},
							{1, 1, Button{
								widgetBase: widgetBase{
									name: "manual",
								},
								text: "Manual Keying",
							}},
							{1, 1, Label{widgetBase: widgetBase{hExpand: true}}},
						},
					},
				}},
			},
		},
	}

	nextRow := len(grid.rows)

	c.gui.Actions() <- SetChild{name: "right", child: rightPane("CREATE CONTACT", nil, nil, grid)}
	c.gui.Actions() <- UIState{uiStateNewContact}
	c.gui.Signal()

	if existing {
		return c.newContactManual(contact, existing, nextRow)
	}

	var keyAgreementClick interface{}

	for {
		event, wanted := c.nextEvent(0)
		if wanted {
			return event
		}

		click, ok := event.(Click)
		if !ok {
			continue
		}

		keyAgreementClick = nil
		switch click.name {
		case "name":
		case "manual", "shared":
			// If the user clicked one of the key-agreement type
			// buttons then we remember the event for the next
			// event loop, below.
			keyAgreementClick = event
		default:
			continue
		}

		name = click.entries["name"]

		if len(name) == 0 {
			continue
		}

		nameIsUnique := true
		for _, contact := range c.contacts {
			if contact.name == name {
				const errText = "A contact by that name already exists!"
				c.gui.Actions() <- SetText{name: "error1", text: errText}
				c.gui.Actions() <- UIError{errors.New(errText)}
				c.gui.Signal()
				nameIsUnique = false
				break
			}
		}

		if nameIsUnique {
			break
		}
	}

	contact = &Contact{
		name:      name,
		isPending: true,
		id:        c.randId(),
	}

	c.gui.Actions() <- SetText{name: "error1", text: ""}
	c.gui.Actions() <- Sensitive{name: "name", sensitive: false}
	c.gui.Signal()

	for {
		var event interface{}
		if keyAgreementClick != nil {
			event, keyAgreementClick = keyAgreementClick, event
		} else {
			var wanted bool
			event, wanted = c.nextEvent(0)
			if wanted {
				return event
			}
		}

		click, ok := event.(Click)
		if !ok {
			continue
		}

		var nextFunc func(*Contact, bool, int) interface{}

		switch click.name {
		case "manual":
			nextFunc = func(contact *Contact, existing bool, nextRow int) interface{} {
				return c.newContactManual(contact, existing, nextRow)
			}
		case "shared":
			nextFunc = func(contact *Contact, existing bool, nextRow int) interface{} {
				return c.newContactPanda(contact, existing, nextRow)
			}
		default:
			continue
		}

		c.gui.Actions() <- Sensitive{name: "manual", sensitive: false}
		c.gui.Actions() <- Sensitive{name: "shared", sensitive: false}
		return nextFunc(contact, existing, nextRow)
	}

	panic("unreachable")
}

func (c *guiClient) newContactManual(contact *Contact, existing bool, nextRow int) interface{} {
	if !existing {
		c.newKeyExchange(contact)
		c.contacts[contact.id] = contact
		c.save()

		c.contactsUI.Add(contact.id, contact.name, "pending", indicatorNone)
		c.contactsUI.Select(contact.id)
	}

	var out bytes.Buffer
	pem.Encode(&out, &pem.Block{Bytes: contact.kxsBytes, Type: keyExchangePEM})
	handshake := string(out.Bytes())

	rows := [][]GridE{
		{
			{1, 1, Label{text: "3."}},
			{1, 1, Label{text: "Give them a handshake message."}},
		},
		{
			{1, 1, nil},
			{1, 1, Label{text: "A handshake is for a single person. Don't give it to anyone else and ensure that it came from the person you intended! For example, you could send it in a PGP signed and encrypted email, or exchange it over an OTR chat.", wrap: 400}},
		},
		{
			{1, 1, nil},
			{1, 1, TextView{
				widgetBase: widgetBase{
					height: 150,
					name:   "kxout",
					font:   fontMainMono,
				},
				editable: false,
				text:     handshake,
			},
			},
		},
		{
			{1, 1, Label{text: "4."}},
			{1, 1, Label{text: "Enter the handshake message from them."}},
		},
		{
			{1, 1, nil},
			{1, 1, Label{text: "You won't be able to exchange messages with them until they complete the handshake.", wrap: 400}},
		},
		{
			{1, 1, nil},
			{1, 1, TextView{
				widgetBase: widgetBase{
					height: 150,
					name:   "kxin",
					font:   fontMainMono,
				},
				editable: true,
			},
			},
		},
		{
			{1, 1, nil},
			{1, 1, Grid{
				widgetBase: widgetBase{marginTop: 20},
				colSpacing: 5,
				rows: [][]GridE{
					{
						{1, 1, Button{
							widgetBase: widgetBase{name: "process"},
							text:       "Process",
						}},
						{1, 1, Button{
							widgetBase: widgetBase{name: "abort"},
							text:       "Abort",
						}},
						{1, 1, Label{widgetBase: widgetBase{hExpand: true}}},
					},
				},
			}},
		},
		{
			{1, 1, nil},
			{1, 1, Label{
				widgetBase: widgetBase{name: "error2", foreground: colorRed},
			}},
		},
	}

	for _, row := range rows {
		c.gui.Actions() <- InsertRow{name: "grid", pos: nextRow, row: row}
		nextRow++
	}
	c.gui.Actions() <- UIState{uiStateNewContact2}
	c.gui.Signal()

	for {
		event, wanted := c.nextEvent(0)
		if wanted {
			return event
		}

		click, ok := event.(Click)
		if !ok {
			continue
		}

		if click.name == "abort" {
			c.gui.Actions() <- Sensitive{name: "abort", sensitive: false}
			c.gui.Signal()
			c.deleteContact(contact)
			c.gui.Actions() <- SetChild{name: "right", child: rightPlaceholderUI}
			c.gui.Actions() <- UIState{uiStateRevocationComplete}
			c.gui.Signal()
			c.save()
			return nil
		}

		if click.name != "process" {
			continue
		}

		block, _ := pem.Decode([]byte(click.textViews["kxin"]))
		if block == nil || block.Type != keyExchangePEM {
			const errText = "No key exchange message found!"
			c.gui.Actions() <- SetText{name: "error2", text: errText}
			c.gui.Actions() <- UIError{errors.New(errText)}
			c.gui.Signal()
			continue
		}
		if err := contact.processKeyExchange(block.Bytes, c.dev, c.simulateOldClient, c.disableV2Ratchet); err != nil {
			c.gui.Actions() <- SetText{name: "error2", text: err.Error()}
			c.gui.Actions() <- UIError{err}
			c.gui.Signal()
			continue
		} else {
			break
		}
	}

	// Unseal all pending messages from this new contact.
	contact.isPending = false
	c.unsealPendingMessages(contact)
	c.contactsUI.SetSubline(contact.id, "")
	c.save()
	return c.showContact(contact.id)
}

func (c *guiClient) newContactPanda(contact *Contact, existing bool, nextRow int) interface{} {
	c.newKeyExchange(contact)

	controls := Grid{
		widgetBase: widgetBase{name: "controls", margin: 5},
		rowSpacing: 5,
		colSpacing: 5,
		rows: [][]GridE{
			{
				{1, 1, Label{
					widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, hAlign: AlignEnd, vAlign: AlignCenter},
					text:       "Shared secret",
				}},
				{2, 1, Grid{
					colSpacing: 5,
					rows: [][]GridE{
						{
							{1, 1, Entry{widgetBase: widgetBase{name: "shared", width: 400}, updateOnChange: true}},
							{1, 1, Button{widgetBase: widgetBase{name: "generate"}, text: "Generate"}},
						},
					},
				}},
			},
			{
				{1, 1, Label{
					widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, hAlign: AlignEnd, vAlign: AlignCenter},
					text:       "Cards",
				}},
				{1, 1, Entry{widgetBase: widgetBase{name: "cardentry"}, updateOnChange: true}},
				{1, 1, RadioGroup{widgetBase: widgetBase{name: "numdecks"}, labels: []string{"1 deck", "2 decks"}}},
			},
			{
				{1, 1, nil},
				{2, 1, Grid{
					widgetBase: widgetBase{name: "cards"},
					rowSpacing: 2,
					colSpacing: 2,
				}},
			},
			{
				{1, 1, Label{
					widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, hAlign: AlignEnd, vAlign: AlignCenter},
					text:       "When",
				}},
				{2, 1, Grid{
					rowSpacing: 5,
					colSpacing: 3,
					rows: [][]GridE{
						{
							{1, 1, CheckButton{widgetBase: widgetBase{name: "hastime"}, text: "Include time"}},
						},
						{
							{1, 1, Calendar{widgetBase: widgetBase{name: "cal", insensitive: true}}},
							{1, 1, Grid{
								widgetBase: widgetBase{marginLeft: 5},
								rowSpacing: 5,
								colSpacing: 3,
								rows: [][]GridE{
									{
										{1, 1, Label{widgetBase: widgetBase{vAlign: AlignCenter}, text: "Hour"}},
										{1, 1, SpinButton{widgetBase: widgetBase{name: "hour", insensitive: true}, min: 0, max: 23, step: 1}},
									},
									{
										{1, 1, Label{widgetBase: widgetBase{vAlign: AlignCenter}, text: "Minute"}},
										{1, 1, SpinButton{widgetBase: widgetBase{name: "minute", insensitive: true}, min: 0, max: 59, step: 1}},
									},
								},
							}},
						},
					},
				}},
			},
			{
				{1, 1, Button{widgetBase: widgetBase{name: "begin"}, text: "Begin"}},
			},
		},
	}

	rows := [][]GridE{
		{
			{1, 1, Label{text: "3."}},
			{1, 1, Label{text: "Enter the shared secret."}},
		},
		{
			{1, 1, nil},
			{1, 1, Label{text: `If you received a secret from someone, enter it as the "Shared secret" and ignore the rest.

If you wish to email/IM a shared secret, click "Generate" to create one and send it to them over email or IM.

If you are agreeing upon the shared secret via other means, then it can be a phrase, or can be generated by shuffling one or two decks of cards together, splitting the stack roughly in half and giving one half to each person. (Or you can do both the card trick and have a phrase.) Additionally, it's possible to use the time of a meeting as a salt if you agreed on it.

When entering cards enter the number or face of the card first, and then the suit - both as single letters. So the three of diamonds is '3d' and the ace of spades is 'as'. Discard the jokers. Click on a card to delete.`, wrap: 400}},
		},
		{
			{1, 1, nil},
			{1, 1, controls},
		},
	}

	for _, row := range rows {
		c.gui.Actions() <- InsertRow{name: "grid", pos: nextRow, row: row}
		nextRow++
	}
	c.gui.Actions() <- UIState{uiStateNewContact2}
	c.gui.Signal()

	const cardsPerRow = 10
	type gridPoint struct {
		col, row int
	}
	// freeList contains the `holes' in the card grid due to cards being
	// deleted.
	var freeList []gridPoint
	// nextPoint contains the next location to insert into the grid of cards.
	var nextPoint gridPoint
	stack := &panda.CardStack{
		NumDecks: 1,
	}
	cardAtLocation := make(map[gridPoint]panda.Card)
	minDecks := 1
	timeEnabled := false

SharedSecretEvent:
	for {
		event, wanted := c.nextEvent(0)
		if wanted {
			return event
		}

		if update, ok := event.(Update); ok && update.name == "shared" {
			ok := panda.IsAcceptableSecretString(update.text)
			c.gui.Actions() <- Sensitive{name: "begin", sensitive: ok}
			c.gui.Signal()
		}

		if update, ok := event.(Update); ok && update.name == "cardentry" && len(update.text) >= 2 {
			cardText := update.text[:2]
			if cardText == "10" {
				if len(update.text) >= 3 {
					cardText = update.text[:3]
				} else {
					continue SharedSecretEvent
				}
			}
			if card, ok := panda.ParseCard(cardText); ok && stack.Add(card) {
				point := nextPoint
				if l := len(freeList); l > 0 {
					point = freeList[l-1]
					freeList = freeList[:l-1]
				} else {
					nextPoint.col++
					if nextPoint.col == cardsPerRow {
						nextPoint.row++
						nextPoint.col = 0
					}
				}
				markup := card.String()
				if card.IsRed() {
					numLen := 1
					if markup[0] == '1' {
						numLen = 2
					}
					markup = markup[:numLen] + "<span color=\"red\">" + markup[numLen:] + "</span>"
				}
				name := fmt.Sprintf("card-%d,%d", point.col, point.row)
				c.gui.Actions() <- GridSet{"cards", point.col, point.row, Button{
					widgetBase: widgetBase{name: name},
					markup:     markup,
				}}
				cardAtLocation[point] = card
				if min := stack.MinimumDecks(); min > minDecks {
					minDecks = min
					if min > 1 {
						c.gui.Actions() <- Sensitive{name: "numdecks", sensitive: false}
					}
				}
			}
			c.gui.Actions() <- SetEntry{name: "cardentry", text: update.text[len(cardText):]}
			c.gui.Signal()
			continue
		}

		if click, ok := event.(Click); ok {
			switch {
			case strings.HasPrefix(click.name, "card-"):
				var point gridPoint
				fmt.Sscanf(click.name[5:], "%d,%d", &point.col, &point.row)
				card := cardAtLocation[point]
				freeList = append(freeList, point)
				delete(cardAtLocation, point)
				stack.Remove(card)
				if min := stack.MinimumDecks(); min < minDecks {
					minDecks = min
					if min < 2 {
						c.gui.Actions() <- Sensitive{name: "numdecks", sensitive: true}
					}
				}
				c.gui.Actions() <- Destroy{name: click.name}
				c.gui.Signal()
			case click.name == "hastime":
				timeEnabled = click.checks["hastime"]
				c.gui.Actions() <- Sensitive{name: "cal", sensitive: timeEnabled}
				c.gui.Actions() <- Sensitive{name: "hour", sensitive: timeEnabled}
				c.gui.Actions() <- Sensitive{name: "minute", sensitive: timeEnabled}
				c.gui.Signal()
			case click.name == "numdecks":
				numDecks := click.radios["numdecks"] + 1
				if numDecks >= minDecks {
					stack.NumDecks = numDecks
				}
			case click.name == "begin":
				secret := panda.SharedSecret{
					Secret: click.entries["shared"],
					Cards:  *stack,
				}
				if timeEnabled {
					date := click.calendars["cal"]
					secret.Year = date.year
					secret.Month = date.month
					secret.Day = date.day
					secret.Hours = click.spinButtons["hour"]
					secret.Minutes = click.spinButtons["minute"]
				}
				mp := c.newMeetingPlace()

				c.contacts[contact.id] = contact
				c.contactsUI.Add(contact.id, contact.name, "pending", indicatorNone)
				c.contactsUI.Select(contact.id)

				kx, err := panda.NewKeyExchange(c.rand, mp, &secret, contact.kxsBytes)
				if err != nil {
					panic(err)
				}
				kx.Testing = c.testing
				contact.pandaKeyExchange = kx.Marshal()
				contact.kxsBytes = nil
				break SharedSecretEvent
			case click.name == "generate":
				c.gui.Actions() <- SetEntry{name: "shared", text: panda.NewSecretString(c.rand)}
				c.gui.Signal()
			}
		}
	}

	c.save()
	c.pandaWaitGroup.Add(1)
	contact.pandaShutdownChan = make(chan struct{})
	go c.runPANDA(contact.pandaKeyExchange, contact.id, contact.name, contact.pandaShutdownChan)
	return c.showContact(contact.id)
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
	gui         GUI
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
func (c *guiClient) maybeProcessDetachmentMsg(event interface{}, ui DetachmentUI) bool {
	if derr, ok := event.(DetachmentError); ok {
		id := derr.id
		if !ui.IsValid(id) {
			return true
		}
		c.gui.Actions() <- Destroy{name: ui.ProgressName(id)}
		c.gui.Actions() <- Append{
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
		c.gui.Signal()
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
		c.gui.Actions() <- SetProgress{
			name:     ui.ProgressName(id),
			s:        prog.status,
			fraction: f,
		}
		c.gui.Signal()
		return true
	}
	if complete, ok := event.(DetachmentComplete); ok {
		id := complete.id
		if !ui.IsValid(id) {
			return true
		}
		c.gui.Actions() <- Destroy{
			name: ui.ProgressName(id),
		}
		ui.OnFinal(id)
		ui.OnSuccess(id, complete.detachment)
		c.gui.Signal()
		return true
	}

	return false
}

func (c *guiClient) updateUsage(validContactSelected bool, draft *Draft) bool {
	usageMessage, over := draft.usageString()
	c.gui.Actions() <- SetText{name: "usage", text: usageMessage}
	color := uint32(colorBlack)
	if over {
		color = colorRed
		c.gui.Actions() <- Sensitive{name: "send", sensitive: false}
	} else if validContactSelected {
		c.gui.Actions() <- Sensitive{name: "send", sensitive: true}
	}
	c.gui.Actions() <- SetForeground{name: "usage", foreground: color}
	return over
}

func (c *guiClient) composeUI(draft *Draft, inReplyTo *InboxMessage) interface{} {
	if draft != nil && inReplyTo != nil {
		panic("draft and inReplyTo both set")
	}

	var contactNames []string
	for _, contact := range c.contacts {
		if !contact.isPending && !contact.revokedUs {
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

	if draft != nil && draft.inReplyTo != 0 {
		for _, msg := range c.inbox {
			if msg.id == draft.inReplyTo {
				inReplyTo = msg
				break
			}
		}
	}

	if draft == nil {
		from := preSelected
		if len(preSelected) == 0 {
			from = "Unknown"
		}

		draft = &Draft{
			id:      c.randId(),
			created: c.Now(),
		}
		if inReplyTo != nil {
			draft.inReplyTo = inReplyTo.id
			draft.to = inReplyTo.from
			draft.body = indentForReply(inReplyTo.message.GetBody())
		}

		c.draftsUI.Add(draft.id, from, draft.created.Format(shortTimeFormat), indicatorNone)
		c.draftsUI.Select(draft.id)
		c.drafts[draft.id] = draft
	}

	initialUsageMessage, overSize := draft.usageString()
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

	c.gui.Actions() <- SetChild{name: "right", child: ui}

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
		c.gui.Actions() <- Append{
			name:     "filesvbox",
			children: initialAttachmentChildren,
		}
	}

	detachmentUI := ComposeDetachmentUI{draft, detachments, c.gui, func() {
		overSize = c.updateUsage(validContactSelected, draft)
	}}

	c.gui.Actions() <- UIState{uiStateCompose}
	c.gui.Signal()

	for {
		event, wanted := c.nextEvent(0)
		if wanted {
			return event
		}

		if update, ok := event.(Update); ok {
			overSize = c.updateUsage(validContactSelected, draft)
			draft.body = update.text
			c.gui.Signal()
			continue
		}

		if open, ok := event.(OpenResult); ok && open.ok && open.arg == nil {
			// Opening a file for an attachment.
			contents, size, err := openAttachment(open.path)
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
					Filename: proto.String(base),
					Contents: contents,
				}
				attachments[id] = len(draft.attachments)
				draft.attachments = append(draft.attachments, a)
			}

			c.gui.Actions() <- Append{
				name: "filesvbox",
				children: []Widget{
					widgetForAttachment(id, label, err != nil, extraWidgets),
				},
			}
			overSize = c.updateUsage(validContactSelected, draft)
			c.gui.Signal()
		}
		if open, ok := event.(OpenResult); ok && open.ok && open.arg != nil {
			// Saving a detachment.
			id := open.arg.(uint64)
			c.gui.Actions() <- Destroy{name: fmt.Sprintf("attachment-addi-%x", id)}
			c.gui.Actions() <- Append{
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
			c.gui.Signal()
		}

		if c.maybeProcessDetachmentMsg(event, detachmentUI) {
			continue
		}

		click, ok := event.(Click)
		if !ok {
			continue
		}
		if click.name == "attach" {
			c.gui.Actions() <- FileOpen{
				title: "Attach File",
			}
			c.gui.Signal()
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
				c.gui.Actions() <- Sensitive{name: "send", sensitive: true}
				c.gui.Signal()
			}
			continue
		}
		if click.name == "discard" {
			c.draftsUI.Remove(draft.id)
			delete(c.drafts, draft.id)
			c.save()
			c.gui.Actions() <- SetChild{name: "right", child: rightPlaceholderUI}
			c.gui.Actions() <- UIState{uiStateMain}
			c.gui.Signal()
			return nil
		}
		if strings.HasPrefix(click.name, "remove-") {
			// One of the attachment remove buttons.
			id, err := strconv.ParseUint(click.name[7:], 16, 64)
			if err != nil {
				panic(click.name)
			}
			c.gui.Actions() <- Destroy{name: "attachment-frame-" + click.name[7:]}
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
			c.gui.Signal()
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
			c.gui.Actions() <- FileOpen{
				save:     true,
				title:    "Save encrypted file",
				filename: filepath.Base(draft.pendingDetachments[id].path) + ".pondencrypted",
				arg:      id,
			}
			c.gui.Signal()
		}
		const uploadPrefix = "attachment-upload-"
		if strings.HasPrefix(click.name, uploadPrefix) {
			idStr := click.name[len(uploadPrefix):]
			id, err := strconv.ParseUint(idStr, 16, 64)
			if err != nil {
				panic(click.name)
			}
			c.gui.Actions() <- Destroy{name: fmt.Sprintf("attachment-addi-%x", id)}
			c.gui.Actions() <- Append{
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
			c.gui.Signal()
		}

		if click.name != "send" {
			continue
		}

		toName := click.combos["to"]
		if len(toName) == 0 {
			continue
		}
		for _, contact := range c.contacts {
			if contact.name == toName {
				draft.to = contact.id
				break
			}
		}

		if inReplyTo != nil {
			draft.inReplyTo = inReplyTo.message.GetId()
		}
		draft.body = click.textViews["body"]

		id, created, err := c.sendDraft(draft)
		if err != nil {
			// TODO: handle this case better.
			println(err.Error())
			c.log.Errorf("Error sending message: %s", err)
			continue
		}
		to := c.contacts[draft.to]
		c.outboxUI.Add(id, to.name, created.Format(shortTimeFormat), indicatorRed)
		if inReplyTo != nil {
			inReplyTo.acked = true
			c.inboxUI.SetIndicator(inReplyTo.id, indicatorNone)
		}

		c.draftsUI.Remove(draft.id)
		delete(c.drafts, draft.id)

		c.save()

		c.outboxUI.Select(id)
		return c.showOutbox(id)
	}

	return nil
}

// unsealPendingMessages is run once a key exchange with a contact has
// completed and unseals any previously unreadable messages from that contact.
func (c *guiClient) unsealPendingMessages(contact *Contact) {
	var needToFilter = true

	for _, msg := range c.inbox {
		if msg.message == nil && msg.from == contact.id {
			if !c.unsealMessage(msg, contact) || len(msg.message.Body) == 0 {
				c.inboxUI.Remove(msg.id)
				needToFilter = true
				continue
			}
			subline := time.Unix(*msg.message.Time, 0).Format(shortTimeFormat)
			c.inboxUI.SetSubline(msg.id, subline)
			c.inboxUI.SetIndicator(msg.id, indicatorBlue)
		}
	}

	if needToFilter {
		c.dropSealedAndAckMessagesFrom(contact)
	}

	c.updateWindowTitle()
}

func (c *guiClient) processPANDAUpdateUI(update pandaUpdate) {
	contact := c.contacts[update.id]

	switch {
	case update.err != nil:
		c.contactsUI.SetSubline(contact.id, "failed")
	case update.serialised != nil:
	case update.result != nil:
		c.contactsUI.SetSubline(contact.id, "")
		c.unsealPendingMessages(contact)
		c.gui.Actions() <- UIState{uiStatePANDAComplete}
		c.gui.Signal()
	}
}

func (c *guiClient) removeInboxMessageUI(msg *InboxMessage) {
	if msg.message == nil || len(msg.message.Body) > 0 {
		c.inboxUI.Remove(msg.id)
	}
}

func (c *guiClient) removeOutboxMessageUI(msg *queuedMessage) {
	if msg.revocation || len(msg.message.Body) > 0 {
		c.outboxUI.Remove(msg.id)
	}
}

func (c *guiClient) addRevocationMessageUI(msg *queuedMessage) {
	c.outboxUI.Add(msg.id, "Revocation", msg.created.Format(shortTimeFormat), indicatorRed)
	c.outboxUI.SetInsensitive(msg.id)
}

func (c *guiClient) removeContactUI(contact *Contact) {
	c.contactsUI.Remove(contact.id)
}

func (c *guiClient) logEventUI(contact *Contact, event Event) {
	c.contactsUI.SetIndicator(contact.id, indicatorBlue)
}

func (c *guiClient) logUI() interface{} {
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
									widgetBase: widgetBase{font: "Arial 16", padding: 10, foreground: colorHeaderForeground},
									text:       "ACTIVITY LOG",
								},
							},
						},
					},
				},
			},
			EventBox{widgetBase: widgetBase{height: 1, background: colorSep}},
			HBox{
				widgetBase: widgetBase{
					padding: 5,
				},
				children: []Widget{
					VBox{
						widgetBase: widgetBase{
							expand: true,
							fill:   true,
						},
					},
					HBox{
						widgetBase: widgetBase{
							padding: 10,
						},
						children: []Widget{
							Button{
								widgetBase: widgetBase{
									name:    "clear-log",
									padding: 2,
								},
								text: "Clear",
							},
							Button{
								widgetBase: widgetBase{
									name:    "transact",
									padding: 2,
								},
								text: "Transact Now",
							},
						},
					},
				},
			},
			Scrolled{
				horizontal: true,
				widgetBase: widgetBase{expand: true, fill: true},
				child: TextView{
					widgetBase: widgetBase{expand: true, fill: true, name: "log"},
					editable:   false,
				},
			},
		},
	}

	log := ""
	lastProcessedIndex := -1

	c.log.Lock()
	logEpoch := c.log.epoch
	for _, entry := range c.log.entries {
		log += fmt.Sprintf("%s: %s\n", entry.Format(logTimeFormat), entry.s)
		lastProcessedIndex++
	}
	c.log.Unlock()

	c.gui.Actions() <- SetChild{name: "right", child: ui}
	c.gui.Actions() <- SetTextView{name: "log", text: log}
	c.gui.Actions() <- UIState{uiStateLog}
	c.gui.Actions() <- ScrollTextViewToEnd{name: "log"}
	c.gui.Signal()

	for {
		event, wanted := c.nextEvent(0)
		if wanted {
			return event
		}

		if click, ok := event.(Click); ok && click.name == "transact" {
			select {
			case c.fetchNowChan <- nil:
			default:
			}
			continue
		}

		if click, ok := event.(Click); ok && click.name == "clear-log" {
			c.log.clear()
			logEpoch = c.log.epoch
			lastProcessedIndex = -1
			log = ""
			c.gui.Actions() <- SetTextView{name: "log", text: log}
			c.gui.Signal()
			continue
		}

		c.log.Lock()
		if logEpoch != c.log.epoch {
			logEpoch = c.log.epoch
			lastProcessedIndex = -1
			log = ""
		}
		for _, entry := range c.log.entries[lastProcessedIndex+1:] {
			log += fmt.Sprintf("%s: %s\n", entry.Format(logTimeFormat), entry.s)
			lastProcessedIndex++
		}
		c.log.Unlock()

		c.gui.Actions() <- SetTextView{name: "log", text: log}
		c.gui.Actions() <- ScrollTextViewToEnd{name: "log"}
		c.gui.Signal()
	}

	return nil
}

func NewGUIClient(stateFilename string, gui GUI, rand io.Reader, testing, autoFetch bool) *guiClient {
	c := &guiClient{
		client: client{
			testing:            testing,
			dev:                testing,
			autoFetch:          autoFetch,
			stateFilename:      stateFilename,
			log:                NewLog(),
			rand:               rand,
			contacts:           make(map[uint64]*Contact),
			drafts:             make(map[uint64]*Draft),
			newMessageChan:     make(chan NewMessage),
			messageSentChan:    make(chan messageSendResult, 1),
			backgroundChan:     make(chan interface{}, 8),
			pandaChan:          make(chan pandaUpdate, 1),
			signingRequestChan: make(chan signingRequest),
			usedIds:            make(map[uint64]bool),
		},
		gui: gui,
	}
	c.ui = c

	if !testing {
		c.timerChan = time.Tick(60 * time.Second)
	}

	c.newMeetingPlace = func() panda.MeetingPlace {
		return &panda.HTTPMeetingPlace{
			TorAddress: c.torAddress,
			URL:        "https://panda-key-exchange.appspot.com/exchange",
		}
	}
	c.log.toStderr = true
	return c
}

func (c *guiClient) Start() {
	go c.loadUI()
}
