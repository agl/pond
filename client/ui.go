package main

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/pond/panda"
	pond "github.com/agl/pond/protos"
)

func (c *client) showInbox(id uint64) interface{} {
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
	if msg.message != nil && !msg.read {
		msg.read = true
		c.inboxUI.SetIndicator(id, indicatorNone)
		c.updateWindowTitle()
		c.save()
	}
	isServerAnnounce := msg.from == 0

	var contact *Contact
	var fromString string
	if isServerAnnounce {
		fromString = "<Home Server>"
	} else {
		contact = c.contacts[msg.from]
		fromString = contact.name
	}
	isPending := msg.message == nil
	var msgText, sentTimeText string
	if isPending {
		msgText = "(cannot display message as key exchange is still pending)"
		sentTimeText = "(unknown)"
	} else {
		sentTimeText = time.Unix(*msg.message.Time, 0).Format(time.RFC1123)
		msgText = "(cannot display message as encoding is not supported)"
		if msg.message.BodyEncoding != nil {
			switch *msg.message.BodyEncoding {
			case pond.Message_RAW:
				msgText = string(msg.message.Body)
			}
		}
	}
	eraseTimeText := msg.receivedTime.Add(messageLifetime).Format(time.RFC1123)

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
				{1, 1, Label{widgetBase: widgetBase{hExpand: true}, text: fromString}},
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
		},
	}

	main := TextView{
		widgetBase: widgetBase{hExpand: true, vExpand: true, name: "body"},
		editable:   false,
		text:       msgText,
		wrap:       true,
	}

	c.ui.Actions() <- SetChild{name: "right", child: rightPane("RECEIVED MESSAGE", left, right, main)}

	// The UI names widgets with strings so these prefixes are used to
	// generate names for the dynamic parts of the UI.
	const (
		detachmentDecryptPrefix  = "detachment-decrypt-"
		detachmentProgressPrefix = "detachment-progress-"
		detachmentDownloadPrefix = "detachment-download-"
		detachmentSavePrefix     = "detachment-save-"
		attachmentPrefix         = "attachment-"
	)

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

		c.ui.Actions() <- InsertRow{name: "lhs", pos: lhsNextRow, row: []GridE{
			{1, 1, Label{
				widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, hAlign: AlignEnd, vAlign: AlignCenter},
				text:       "ATTACHMENTS",
			}},
		}}
		lhsNextRow++
		c.ui.Actions() <- InsertRow{name: "lhs", pos: lhsNextRow, row: []GridE{{2, 1, grid}}}
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
				progressRow = append(progressRow, GridE{4, 1,
					Progress{
						widgetBase: widgetBase{
							name: fmt.Sprintf("%s%d", detachmentProgressPrefix, i),
						},
					},
				})
			}
			grid.rows = append(grid.rows, row)
			grid.rows = append(grid.rows, progressRow)
		}

		c.ui.Actions() <- InsertRow{name: "lhs", pos: lhsNextRow, row: []GridE{
			{1, 1, Label{
				widgetBase: widgetBase{font: fontMainLabel, foreground: colorHeaderForeground, hAlign: AlignEnd, vAlign: AlignCenter},
				text:       "KEYS",
			}},
		}}
		lhsNextRow++
		c.ui.Actions() <- InsertRow{name: "lhs", pos: lhsNextRow, row: []GridE{{2, 1, grid}}}
		lhsNextRow++
		c.ui.Signal()
	}

	c.ui.Actions() <- UIState{uiStateInbox}
	c.ui.Signal()

	detachmentUI := InboxDetachmentUI{msg, c.ui}

	if msg.decryptions == nil {
		msg.decryptions = make(map[uint64]*pendingDecryption)
	}

NextEvent:
	for {
		event, wanted := c.nextEvent()
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
				c.ui.Actions() <- FileOpen{
					save:  true,
					title: "Save decrypted file",
					arg: detachmentDecryptInput{
						index:  int(i),
						inPath: open.path,
					},
				}
				c.ui.Signal()
			case detachmentDecryptInput:
				// Decrypt a local file with a detachment key,
				// after the second save dialog - which prompts
				// for where to write the new key.
				for _, decryption := range msg.decryptions {
					if decryption.index == i.index {
						continue NextEvent
					}
				}
				c.ui.Actions() <- Sensitive{
					name:      fmt.Sprintf("%s%d", detachmentDecryptPrefix, i.index),
					sensitive: false,
				}
				c.ui.Actions() <- Sensitive{
					name:      fmt.Sprintf("%s%d", detachmentDownloadPrefix, i.index),
					sensitive: false,
				}
				c.ui.Actions() <- InsertRow{
					name: "detachment-grid",
					pos:  i.index*2 + 1,
					row: []GridE{
						{4, 1, Progress{
							widgetBase: widgetBase{
								name: fmt.Sprintf("%s%d", detachmentProgressPrefix, i.index),
							},
						}},
					},
				}
				id := c.randId()
				msg.decryptions[id] = &pendingDecryption{
					index:  i.index,
					cancel: c.startDecryption(id, open.path, i.inPath, msg.message.DetachedFiles[i.index]),
				}
				c.ui.Signal()
			case detachmentDownloadIndex:
				// Download a detachment.
				for _, decryption := range msg.decryptions {
					if decryption.index == int(i) {
						continue NextEvent
					}
				}
				c.ui.Actions() <- Sensitive{
					name:      fmt.Sprintf("%s%d", detachmentDecryptPrefix, i),
					sensitive: false,
				}
				c.ui.Actions() <- Sensitive{
					name:      fmt.Sprintf("%s%d", detachmentDownloadPrefix, i),
					sensitive: false,
				}
				c.ui.Actions() <- InsertRow{
					name: "detachment-grid",
					pos:  int(i)*2 + 1,
					row: []GridE{
						{4, 1, Progress{
							widgetBase: widgetBase{
								name: fmt.Sprintf("%s%d", detachmentProgressPrefix, int(i)),
							},
						}},
					},
				}
				id := c.randId()
				msg.decryptions[id] = &pendingDecryption{
					index:  int(i),
					cancel: c.startDownload(id, open.path, msg.message.DetachedFiles[i]),
				}
				c.ui.Signal()
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
			c.ui.Actions() <- FileOpen{
				save:  true,
				title: "Save Attachment",
				arg:   attachmentSaveIndex(i),
			}
			c.ui.Signal()
			continue
		case strings.HasPrefix(click.name, detachmentSavePrefix):
			i, _ := strconv.Atoi(click.name[len(detachmentSavePrefix):])
			c.ui.Actions() <- FileOpen{
				save:  true,
				title: "Save Key",
				arg:   detachmentSaveIndex(i),
			}
			c.ui.Signal()
			continue
		case strings.HasPrefix(click.name, detachmentDecryptPrefix):
			i, _ := strconv.Atoi(click.name[len(detachmentDecryptPrefix):])
			c.ui.Actions() <- FileOpen{
				title: "Select encrypted file",
				arg:   detachmentDecryptIndex(i),
			}
			c.ui.Signal()
			continue
		case strings.HasPrefix(click.name, detachmentDownloadPrefix):
			i, _ := strconv.Atoi(click.name[len(detachmentDownloadPrefix):])
			c.ui.Actions() <- FileOpen{
				title: "Save to",
				arg:   detachmentDownloadIndex(i),
			}
			c.ui.Signal()
			continue
		case click.name == "ack":
			c.ui.Actions() <- Sensitive{name: "ack", sensitive: false}
			c.ui.Signal()
			msg.acked = true
			c.sendAck(msg)
			c.ui.Actions() <- UIState{uiStateInbox}
			c.ui.Signal()
		case click.name == "reply":
			c.inboxUI.Deselect()
			return c.composeUI(nil, msg)
		case click.name == "delete":
			c.inboxUI.Remove(msg.id)
			newInbox := make([]*InboxMessage, 0, len(c.inbox))
			for _, inboxMsg := range c.inbox {
				if inboxMsg == msg {
					continue
				}
				newInbox = append(newInbox, inboxMsg)
			}
			c.inbox = newInbox
			c.ui.Actions() <- SetChild{name: "right", child: rightPlaceholderUI}
			c.ui.Actions() <- UIState{uiStateMain}
			c.ui.Signal()
			c.save()
			return nil
		}
	}

	return nil
}

func (c *client) showOutbox(id uint64) interface{} {
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
		},
	}

	main := TextView{
		widgetBase: widgetBase{vExpand: true, hExpand: true, name: "body"},
		editable:   false,
		text:       string(msg.message.Body),
		wrap:       true,
	}

	c.ui.Actions() <- SetChild{name: "right", child: rightPane("SENT MESSAGE", left, nil, main)}
	c.ui.Actions() <- UIState{uiStateOutbox}
	c.ui.Signal()

	haveSentTime := !msg.sent.IsZero()
	haveAckTime := !msg.acked.IsZero()

	for {
		event, wanted := c.nextEvent()
		if wanted {
			return event
		}

		if !haveSentTime && !msg.sent.IsZero() {
			c.ui.Actions() <- SetText{name: "sent", text: formatTime(msg.sent)}
			c.ui.Signal()
		}
		if !haveAckTime && !msg.acked.IsZero() {
			c.ui.Actions() <- SetText{name: "acked", text: formatTime(msg.acked)}
			c.ui.Signal()
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

func (c *client) identityUI() interface{} {
	left := nameValuesLHS([]nvEntry{
		{"SERVER", c.server},
		{"PUBLIC IDENTITY", fmt.Sprintf("%x", c.identityPublic[:])},
		{"PUBLIC KEY", fmt.Sprintf("%x", c.pub[:])},
		{"STATE FILE", c.stateFilename},
		{"GROUP GENERATION", fmt.Sprintf("%d", c.generation)},
	})

	c.ui.Actions() <- SetChild{name: "right", child: rightPane("IDENTITY", left, nil, nil)}
	c.ui.Actions() <- UIState{uiStateShowIdentity}
	c.ui.Signal()

	return nil
}

func (c *client) showContact(id uint64) interface{} {
	contact := c.contacts[id]
	if contact.isPending && len(contact.pandaKeyExchange) == 0 && len(contact.pandaResult) == 0 {
		return c.newContactUI(contact)
	}

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

	right := Grid{
		widgetBase: widgetBase{margin: 6},
		rowSpacing: 3,
		colSpacing: 3,
		rows: [][]GridE{
			{
				{1, 1, Button{
					widgetBase: widgetBase{
						name:        "revoke",
						insensitive: contact.revoked,
					},
					text: "Revoke",
				}},
			},
			{
				{1, 1, Button{
					widgetBase: widgetBase{
						name:        "delete",
						insensitive: true,
					},
					text: "Delete",
				}},
			},
		},
	}

	left := nameValuesLHS(entries)
	c.ui.Actions() <- SetChild{name: "right", child: rightPane("CONTACT", left, right, nil)}
	c.ui.Actions() <- UIState{uiStateShowContact}
	c.ui.Signal()

	for {
		event, wanted := c.nextEvent()
		if wanted {
			return event
		}

		click, ok := event.(Click)
		if !ok {
			continue
		}

		if click.name == "revoke" {
			c.revoke(contact)
			c.ui.Actions() <- Sensitive{name: "revoke", sensitive: false}
			c.ui.Signal()
			c.save()
		}
	}

	panic("unreachable")
}

func (c *client) newContactUI(contact *Contact) interface{} {
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
				{1, 1, Label{text: `Manual keying involves exchanging key material with your contact in a secure and authentic manner, i.e. by using PGP. The security of Pond is moot if you actually exchange keys with an attacker: they can masquerade the intended contact or could simply do the same to them and pass messages between you, reading everything in the process. Note that the key material is also secret - it's not a public key and so must be encrypted as well as signed.

Shared secret keying involves anonymously contacting a global, shared service and performing key agreement with another party who holds the same shared secret and shared time as you. For example, if you met your contact in real life, you could agree on a shared secret and the time (to the minute). Later you can both use this function to bootstrap Pond communication. The security of this scheme rests on the secret being unguessable, which is very hard for humans to manage. So there is also a scheme whereby a deck of cards can be shuffled and split between you.`, wrap: 400}},
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
									name:        "manual",
									insensitive: true,
								},
								text: "Manual Keying",
							}},
							{1, 1, Label{widgetBase: widgetBase{hExpand: true}}},
							{1, 1, Button{
								widgetBase: widgetBase{
									name:        "shared",
									insensitive: true,
								},
								text: "Shared secret",
							}},
							{1, 1, Label{widgetBase: widgetBase{hExpand: true}}},
						},
					},
				}},
			},
		},
	}

	nextRow := len(grid.rows)

	c.ui.Actions() <- SetChild{name: "right", child: rightPane("CREATE CONTACT", nil, nil, grid)}
	c.ui.Actions() <- UIState{uiStateNewContact}
	c.ui.Signal()

	if existing {
		return c.newContactManual(contact, existing, nextRow)
	}

	for {
		event, wanted := c.nextEvent()
		if wanted {
			return event
		}

		click, ok := event.(Click)
		if !ok {
			continue
		}
		if click.name != "name" {
			continue
		}

		name = click.entries["name"]

		nameIsUnique := true
		for _, contact := range c.contacts {
			if contact.name == name {
				const errText = "A contact by that name already exists!"
				c.ui.Actions() <- SetText{name: "error1", text: errText}
				c.ui.Actions() <- UIError{errors.New(errText)}
				c.ui.Signal()
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

	c.contactsUI.Add(contact.id, name, "pending", indicatorNone)
	c.contactsUI.Select(contact.id)

	c.ui.Actions() <- SetText{name: "error1", text: ""}
	c.ui.Actions() <- Sensitive{name: "name", sensitive: false}
	c.ui.Actions() <- Sensitive{name: "manual", sensitive: true}
	c.ui.Actions() <- Sensitive{name: "shared", sensitive: true}
	c.ui.Signal()

	for {
		event, wanted := c.nextEvent()
		if wanted {
			return event
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

		c.ui.Actions() <- Sensitive{name: "manual", sensitive: false}
		c.ui.Actions() <- Sensitive{name: "shared", sensitive: false}
		return nextFunc(contact, existing, nextRow)
	}

	panic("unreachable")
}

func (c *client) newContactManual(contact *Contact, existing bool, nextRow int) interface{} {
	if !existing {
		c.newKeyExchange(contact)
		c.contacts[contact.id] = contact
		c.save()
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
				rows: [][]GridE{
					{
						{1, 1, Button{
							widgetBase: widgetBase{name: "process"},
							text:       "Process",
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
		c.ui.Actions() <- InsertRow{name: "grid", pos: nextRow, row: row}
		nextRow++
	}
	c.ui.Actions() <- UIState{uiStateNewContact2}
	c.ui.Signal()

	for {
		event, wanted := c.nextEvent()
		if wanted {
			return event
		}

		click, ok := event.(Click)
		if !ok {
			continue
		}
		if click.name != "process" {
			continue
		}

		block, _ := pem.Decode([]byte(click.textViews["kxin"]))
		if block == nil || block.Type != keyExchangePEM {
			const errText = "No key exchange message found!"
			c.ui.Actions() <- SetText{name: "error2", text: errText}
			c.ui.Actions() <- UIError{errors.New(errText)}
			c.ui.Signal()
			continue
		}
		if err := contact.processKeyExchange(block.Bytes, c.testing); err != nil {
			c.ui.Actions() <- SetText{name: "error2", text: err.Error()}
			c.ui.Actions() <- UIError{err}
			c.ui.Signal()
			continue
		} else {
			break
		}
	}

	// Unseal all pending messages from this new contact.
	c.unsealPendingMessages(contact)
	c.contactsUI.SetSubline(contact.id, "")
	c.save()
	return c.showContact(contact.id)
}

func (c *client) newContactPanda(contact *Contact, existing bool, nextRow int) interface{} {
	c.newKeyExchange(contact)
	c.contacts[contact.id] = contact

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
				{2, 1, Entry{widgetBase: widgetBase{name: "shared"}}},
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
			{1, 1, Label{text: `The shared secret can be a phrase, or can be generated by shuffling one or two decks of cards together, splitting the stack roughly in half and giving one half to each person. (Or you can do both the card trick and have a phrase.) Additionally, it's possible to use the time of the meeting as a salt if you agreed on it.

When entering the cards enter the number or face of the card first, and then the suite - both as single letters. So the three of dimonds is '3d' and the ace of spades is 'as'. Discard the jokers. Click on a card to delete.`, wrap: 400}},
		},
		{
			{1, 1, nil},
			{1, 1, controls},
		},
	}

	for _, row := range rows {
		c.ui.Actions() <- InsertRow{name: "grid", pos: nextRow, row: row}
		nextRow++
	}
	c.ui.Actions() <- UIState{uiStateNewContact2}
	c.ui.Signal()

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
		event, wanted := c.nextEvent()
		if wanted {
			return event
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
				c.ui.Actions() <- GridSet{"cards", point.col, point.row, Button{
					widgetBase: widgetBase{name: name},
					markup:     markup,
				}}
				cardAtLocation[point] = card
				if min := stack.MinimumDecks(); min > minDecks {
					minDecks = min
					if min > 1 {
						c.ui.Actions() <- Sensitive{name: "numdecks", sensitive: false}
					}
				}
			}
			c.ui.Actions() <- SetEntry{name: "cardentry", text: update.text[len(cardText):]}
			c.ui.Signal()
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
						c.ui.Actions() <- Sensitive{name: "numdecks", sensitive: true}
					}
				}
				c.ui.Actions() <- Destroy{name: click.name}
				c.ui.Signal()
			case click.name == "hastime":
				timeEnabled = click.checks["hastime"]
				c.ui.Actions() <- Sensitive{name: "cal", sensitive: timeEnabled}
				c.ui.Actions() <- Sensitive{name: "hour", sensitive: timeEnabled}
				c.ui.Actions() <- Sensitive{name: "minute", sensitive: timeEnabled}
				c.ui.Signal()
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
				kx, err := panda.NewKeyExchange(c.rand, mp, &secret, contact.kxsBytes)
				if err != nil {
					panic(err)
				}
				kx.Testing = c.testing
				contact.pandaKeyExchange = kx.Marshal()
				contact.kxsBytes = nil
				break SharedSecretEvent
			}
		}
	}

	c.save()
	c.pandaWaitGroup.Add(1)
	go c.runPANDA(contact.pandaKeyExchange, contact.id, contact.name)
	return c.showContact(contact.id)
}
