package main

import (
	"bytes"
	"fmt"
	"encoding/pem"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"code.google.com/p/goprotobuf/proto"
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
						name:        "delete",
						insensitive: true,
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
					widgetBase: widgetBase{name: fmt.Sprintf("attachment-%d", i)},
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
						name:        fmt.Sprintf("detachment-decrypt-%d", i),
						padding:     3,
						insensitive: pending != nil,
					},
					text: "Decrypt file",
				}},
				{1, 1, Button{
					widgetBase: widgetBase{
						name:    fmt.Sprintf("detachment-save-%d", i),
						padding: 3,
					},
					text: "Save",
				}},
			}
			if detachment.Url != nil && len(*detachment.Url) > 0 {
				row = append(row, GridE{1, 1,
					Button{
						widgetBase: widgetBase{
							name:        fmt.Sprintf("detachment-download-%d", i),
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
							name: fmt.Sprintf("detachment-progress-%d", i),
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
	}

	c.ui.Actions() <- UIState{uiStateInbox}
	c.ui.Signal()

	detachmentUI := InboxDetachmentUI{msg, c.ui}

	const detachmentDecryptPrefix = "detachment-decrypt-"
	const detachmentProgressPrefix = "detachment-progress-"
	const detachmentDownloadPrefix = "detachment-download-"

	if msg.decryptions == nil {
		msg.decryptions = make(map[uint64]*pendingDecryption)
	}

	for {
		event, wanted := c.nextEvent()
		if wanted {
			return event
		}

		type attachmentSaveIndex int
		type detachmentSaveIndex int
		type detachmentDecryptIndex int
		type detachmentDecryptInput struct {
			index  int
			inPath string
		}
		type detachmentDownloadIndex int

		if open, ok := event.(OpenResult); ok && open.ok {
			switch i := open.arg.(type) {
			case attachmentSaveIndex:
				ioutil.WriteFile(open.path, msg.message.Files[i].Contents, 0600)
			case detachmentSaveIndex:
				bytes, err := proto.Marshal(msg.message.DetachedFiles[i])
				if err != nil {
					panic(err)
				}
				ioutil.WriteFile(open.path, bytes, 0600)
			case detachmentDecryptIndex:
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
								name: fmt.Sprintf("detachment-progress-%d", i.index),
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
					pos:  int(i) + 1,
					row: []GridE{
						{4, 1, Progress{
							widgetBase: widgetBase{
								name: fmt.Sprintf("detachment-progress-%d", int(i)),
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
		const attachmentPrefix = "attachment-"
		if strings.HasPrefix(click.name, attachmentPrefix) {
			i, _ := strconv.Atoi(click.name[len(attachmentPrefix):])
			c.ui.Actions() <- FileOpen{
				save:  true,
				title: "Save Attachment",
				arg:   attachmentSaveIndex(i),
			}
			c.ui.Signal()
			continue
		}
		const detachmentSavePrefix = "detachment-save-"
		if strings.HasPrefix(click.name, detachmentSavePrefix) {
			i, _ := strconv.Atoi(click.name[len(detachmentSavePrefix):])
			c.ui.Actions() <- FileOpen{
				save:  true,
				title: "Save Key",
				arg:   detachmentSaveIndex(i),
			}
			c.ui.Signal()
			continue
		}
		if strings.HasPrefix(click.name, detachmentDecryptPrefix) {
			i, _ := strconv.Atoi(click.name[len(detachmentDecryptPrefix):])
			c.ui.Actions() <- FileOpen{
				title: "Select encrypted file",
				arg:   detachmentDecryptIndex(i),
			}
			c.ui.Signal()
			continue
		}
		if strings.HasPrefix(click.name, detachmentDownloadPrefix) {
			i, _ := strconv.Atoi(click.name[len(detachmentDownloadPrefix):])
			c.ui.Actions() <- FileOpen{
				title: "Save to",
				arg:   detachmentDownloadIndex(i),
			}
			c.ui.Signal()
			continue
		}
		switch click.name {
		case "ack":
			c.ui.Actions() <- Sensitive{name: "ack", sensitive: false}
			c.ui.Signal()
			msg.acked = true
			c.sendAck(msg)
			c.ui.Actions() <- UIState{uiStateInbox}
			c.ui.Signal()
		case "reply":
			c.inboxUI.Deselect()
			return c.composeUI(nil, msg)
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
	if contact.isPending {
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

	if len(contact.kxsBytes) > 0 {
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
}
