package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa -framework QuartzCore

#include "gui_cocoa.m"
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/pond/client/disk"
	"github.com/agl/pond/panda"
	pond "github.com/agl/pond/protos"
)

const haveGUI = true

type cocoaCommand struct {
	cmd uint
	i   uint64
	s   string
}

type cocoaEvent struct {
	event uint
	i     uint64
	data  []byte
}

type cocoaClient struct {
	client

	signalReadFD  int
	signalWriteFD int
	actions       chan cocoaCommand
	events        chan cocoaEvent
	composes      map[uint64]*activeCompose
}

func (c *cocoaClient) sendCocoaCommand(cmd cocoaCommand) {
	var buf [1]byte

	c.actions <- cmd
	syscall.Write(c.signalWriteFD, buf[:])
}

var (
	cocoaDataTruncated = errors.New("data from Cocoa truncated")
	cocoaDataTooLarge  = errors.New("Cocoa data contains oversized value")
)

type guiTable struct {
	Superfluous bool
	NameColumn  string
	TimeColumn  string
	Rows        []guiTableRow
}

type guiTableRow struct {
	Indicator             uint32
	Name, Extra, Contents string
	Id                    uint64
}

type guiKeyValue struct {
	Key, Value string
}

type guiContents struct {
	Headers []guiKeyValue
	Body    string
}

type guiCompose struct {
	Id    uint64
	Names []string
}

type guiError struct {
	Error string
}

type activeCompose struct {
	id                       uint64
	draft                    *Draft
	attachments              map[uint64]int
	detachments              map[uint64]int
	pendingDetachmentPath    string
	pendingDetachmentsCancel func()
}

func marshalCocoaData(in interface{}) string {
	var out bytes.Buffer
	marshalCocoaDataTo(&out, reflect.ValueOf(in))
	return string(out.Bytes())
}

func marshalCocoaDataTo(out io.Writer, v reflect.Value) {
	switch t := v.Type(); t.Kind() {
	case reflect.String:
		s := v.String()
		binary.Write(out, binary.LittleEndian, uint32(len(s)))
		out.Write([]byte(s))
	case reflect.Uint32:
		binary.Write(out, binary.LittleEndian, uint32(v.Uint()))
	case reflect.Uint64:
		binary.Write(out, binary.LittleEndian, uint64(v.Uint()))
	case reflect.Bool:
		var b uint8
		if v.Bool() {
			b = 1
		}
		binary.Write(out, binary.LittleEndian, b)
	case reflect.Slice:
		l := v.Len()
		binary.Write(out, binary.LittleEndian, uint32(l))
		for i := 0; i < l; i++ {
			marshalCocoaDataTo(out, v.Index(i))
		}
	case reflect.Struct:
		for i, n := 0, v.NumField(); i < n; i++ {
			marshalCocoaDataTo(out, v.Field(i))
		}
	default:
		panic("unknown type")
	}
}

func unmarshalCocoaData(out interface{}, data []byte) error {
	v := reflect.ValueOf(out).Elem()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		t := field.Type()
		switch t.Kind() {
		case reflect.String:
			if len(data) < 4 {
				return cocoaDataTruncated
			}
			l := binary.LittleEndian.Uint32(data)
			data = data[4:]
			if l > 256*1024*1024 {
				return cocoaDataTooLarge
			}
			field.SetString(string(data[:l]))
			data = data[l:]
		default:
			return errors.New("unknown type while unmarshaling Cocoa data")
		}
	}

	if len(data) > 0 {
		return errors.New("trailing data from Cocoa")
	}

	return nil
}

func (c *cocoaClient) initUI() {
	var pngData bytes.Buffer

	binary.Write(&pngData, binary.LittleEndian, uint32(len(indicatorPNGBytes)))
	for _, png := range indicatorPNGBytes {
		binary.Write(&pngData, binary.LittleEndian, uint32(len(png)))
		pngData.Write(png)
	}

	c.sendCocoaCommand(cocoaCommand{cmd: C.SET_INDICATOR_IMAGES, s: string(pngData.Bytes())})
}

func (c *cocoaClient) loadingUI() {}

func (c *cocoaClient) torPromptUI() error {
	c.sendCocoaCommand(cocoaCommand{cmd: C.SHOW_TOR_PROMPT})

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

WaitForTor:
	for {
		select {
		case _, ok := <-c.events:
			if !ok {
				c.ShutdownAndSuspend()
			}
		case <-ticker.C:
			if c.detectTor() {
				break WaitForTor
			}
		}
	}

	c.sendCocoaCommand(cocoaCommand{cmd: C.DESTROY_TOR_PROMPT})

	return nil
}

func (c *cocoaClient) sleepUI(d time.Duration) error {
	return nil
}

func (c *cocoaClient) errorUI(msg string, fatal bool) {}

func (c *cocoaClient) ShutdownAndSuspend() error {
	return nil
}

func (c *cocoaClient) createPassphraseUI() (string, error) {
	c.sendCocoaCommand(cocoaCommand{cmd: C.SHOW_CREATE_PASSPHRASE})
	event := <-c.events

	var data struct {
		Passphrase string
	}
	if err := unmarshalCocoaData(&data, event.data); err != nil {
		panic(err)
	}
	return data.Passphrase, nil
}

func (c *cocoaClient) createAccountUI(stateFile *disk.StateFile, pw string) (bool, error) {
	defaultServer := msgDefaultServer
	if c.dev {
		defaultServer = msgDefaultDevServer
	}

	c.sendCocoaCommand(cocoaCommand{cmd: C.SHOW_CREATE_ACCOUNT, s: defaultServer})

	for {
		event := <-c.events
		if event.event != C.CREATE_ACCOUNT_ENTERED {
			panic(event.event)
		}
		var data struct {
			Server string
		}
		if err := unmarshalCocoaData(&data, event.data); err != nil {
			panic(err)
		}
		c.server = data.Server

		updateMsg := func(msg string) {
			c.sendCocoaCommand(cocoaCommand{cmd: C.UPDATE_CREATE_ACCOUNT, s: msg})
		}

		if err := c.doCreateAccount(updateMsg); err != nil {
			c.sendCocoaCommand(cocoaCommand{cmd: C.UPDATE_CREATE_ACCOUNT, s: err.Error(), i: 1})
			continue
		}
		break
	}

	c.sendCocoaCommand(cocoaCommand{cmd: C.DESTROY_CREATE_ACCOUNT})

	return false, nil
}

func (c *cocoaClient) keyPromptUI(stateFile *disk.StateFile) error {
	return nil
}

func contentsSummary(body string) string {
	const limit = 512
	if len(body) > limit {
		body = body[:limit]
	}
	return strings.Join(strings.Fields(body), " ")
}

func (c *cocoaClient) draftsClicked(event cocoaEvent) {
	draft := c.drafts[event.i]
	if draft == nil {
		return
	}

	var name string
	if draft.to != 0 {
		name = c.contacts[draft.to].name
	}

	contents := guiContents{
		Headers: []guiKeyValue{
			{"TO", name},
			{"CREATED", draft.created.Format(shortTimeFormat)},
		},
		Body: draft.body,
	}

	c.sendCocoaCommand(cocoaCommand{cmd: C.SET_CONTENTS, s: marshalCocoaData(contents)})
}

func (c *cocoaClient) contactsClicked(event cocoaEvent) {
	contact := c.contacts[event.i]
	if contact == nil {
		return
	}
	contents := guiContents{
		Headers: []guiKeyValue{
			{"NAME", contact.name},
			{"SERVER", contact.theirServer},
			{"PUBLIC IDENTITY", fmt.Sprintf("%x", contact.theirIdentityPublic[:])},
			{"PUBLIC KEY", fmt.Sprintf("%x", contact.theirPub[:])},
			{"LAST DH", fmt.Sprintf("%x", contact.theirLastDHPublic[:])},
			{"CURRENT DH", fmt.Sprintf("%x", contact.theirCurrentDHPublic[:])},
			{"GROUP GENERATION", fmt.Sprintf("%d", contact.generation)},
			{"CLIENT VERSION", fmt.Sprintf("%d", contact.supportedVersion)},
		},
	}
	c.sendCocoaCommand(cocoaCommand{cmd: C.SET_CONTENTS, s: marshalCocoaData(contents)})
}

func (c *cocoaClient) updateComposeUsage(compose *activeCompose) {
	usageMessage, over := compose.draft.usageString()

	overInt := uint32(0)
	if over {
		overInt = 1
	}

	c.sendCocoaCommand(cocoaCommand{cmd: C.UPDATE_USAGE, i: compose.id, s: marshalCocoaData(struct {
		Msg  string
		Over uint32
	}{
		usageMessage,
		overInt,
	})})
}

func (c *cocoaClient) mainUI() {
	var currentClickCallback func(cocoaEvent)
	// backgroundTasks maps from a detachment id to the compose window that
	// is currently processing that detachment.
	backgroundTasks := make(map[uint64]*activeCompose)

NextEvent:
	for {
		select {
		case sigReq := <-c.signingRequestChan:
			c.processSigningRequest(sigReq)
		case event, ok := <-c.events:
			if !ok {
				c.ShutdownAndSuspend()
			}
			switch event.event {
			case C.NEW_CONTACT:
				var data struct {
					Name, Secret string
				}
				if err := unmarshalCocoaData(&data, event.data); err != nil {
					panic(err)
				}
				for _, contact := range c.contacts {
					if contact.name == data.Name {
						c.sendCocoaCommand(cocoaCommand{cmd: C.NEW_CONTACT_REJECTED, s: "A contact with that name already exists"})
						continue NextEvent
					}
				}
				c.sendCocoaCommand(cocoaCommand{cmd: C.NEW_CONTACT_ACCEPTED})

			case C.OUTLINE_CLICKED:
				var data struct {
					Label string
				}
				if err := unmarshalCocoaData(&data, event.data); err != nil {
					panic(err)
				}

				var table guiTable

				switch data.Label {
				case "Drafts":
					table.NameColumn = "To"
					table.TimeColumn = "Created"
					for id, draft := range c.drafts {
						var name string
						if draft.to != 0 {
							name = c.contacts[draft.to].name
						}

						table.Rows = append(table.Rows, guiTableRow{
							Indicator: uint32(indicatorNone),
							Name:      name,
							Extra:     draft.created.Format(shortTimeFormat),
							Contents:  contentsSummary(draft.body),
							Id:        id,
						})
					}
					currentClickCallback = c.draftsClicked

				case "Contacts":
					table.NameColumn = "Name"
					for id, contact := range c.contacts {
						table.Rows = append(table.Rows, guiTableRow{
							Indicator: uint32(contact.indicator()),
							Name:      contact.name,
							Id:        id,
						})
					}
					currentClickCallback = c.contactsClicked

				case "Log":
					table.Superfluous = true

					contents := guiContents{
						Body: "Testing",
					}
					c.sendCocoaCommand(cocoaCommand{cmd: C.SET_CONTENTS, s: marshalCocoaData(contents)})
				}

				c.sendCocoaCommand(cocoaCommand{cmd: C.SET_TABLE_CONTENTS, s: marshalCocoaData(table)})

			case C.TABLE_CLICKED:
				if currentClickCallback == nil {
					continue
				}
				currentClickCallback(event)
			case C.COMPOSE:
				id := c.randId()
				compose := &activeCompose{
					id:          id,
					attachments: make(map[uint64]int),
					detachments: make(map[uint64]int),
					draft: &Draft{
						id:      id,
						created: c.Now(),
					},
				}
				c.composes[id] = compose
				c.drafts[id] = compose.draft

				var names []string
				for _, contact := range c.contacts {
					if !contact.isPending && !contact.revokedUs {
						names = append(names, contact.name)
					}
				}
				c.sendCocoaCommand(cocoaCommand{cmd: C.OPEN_COMPOSE, s: marshalCocoaData(struct {
					Id    uint64
					Names []string
				}{
					id,
					names,
				})})
				c.updateComposeUsage(c.composes[id])
			case C.ATTACH:
				path := string(event.data)
				contents, size, err := openAttachment(path)
				if err != nil {
					c.sendCocoaCommand(cocoaCommand{cmd: C.COMPOSE_ERROR, i: event.i, s: marshalCocoaData(guiError{
						Error: err.Error(),
					})})
					break
				}

				compose := c.composes[event.i]
				draft := compose.draft
				base := filepath.Base(path)

				if size >= 0 {
					c.sendCocoaCommand(cocoaCommand{cmd: C.PROMPT_DETACHMENT, i: event.i, s: marshalCocoaData(struct {
						Msg string
					}{
						fmt.Sprintf("The attachment (%s) is too large to include in a Pond message (%s bytes). You can either upload the encrypted file to the Pond server (which generates a clear traffic signal to an observer) or you can save an encrypted version to disk and include only the key in the Pond message. In the latter case, you need to transport the encrypted file to the recipient yourself.", base, prettyNumber(uint64(size))),
					})})
					compose.pendingDetachmentPath = path

					break
				}

				a := &pond.Message_Attachment{
					Filename: proto.String(base),
					Contents: contents,
				}
				id := c.randId()
				compose.attachments[id] = len(draft.attachments)

				draft.attachments = append(draft.attachments, a)

				c.sendCocoaCommand(cocoaCommand{cmd: C.ADD_ATTACHMENT, i: event.i, s: marshalCocoaData(struct {
					Label string
					Id    uint64
				}{
					Label: fmt.Sprintf("%s (%s bytes)", base, prettyNumber(uint64(len(contents)))),
					Id:    id,
				})})
				c.updateComposeUsage(compose)
			case C.SAVE_ENCRYPTED:
				path := string(event.data)
				compose := c.composes[event.i]
				id := c.randId()
				backgroundTasks[id] = compose
				compose.pendingDetachmentsCancel = c.startEncryption(id, path, compose.pendingDetachmentPath)
				compose.pendingDetachmentPath = ""
			case C.UPLOAD:
				compose := c.composes[event.i]
				id := c.randId()
				backgroundTasks[id] = compose
				compose.pendingDetachmentsCancel = c.startUpload(id, compose.pendingDetachmentPath)
				compose.pendingDetachmentPath = ""
			case C.CANCEL_DETACHMENT:
				compose := c.composes[event.i]
				compose.pendingDetachmentsCancel()
				compose.pendingDetachmentsCancel = nil
			case C.REMOVE_ATTACHMENT:
				compose := c.composes[event.i]
				draft := compose.draft
				id := binary.LittleEndian.Uint64(event.data)
				index := compose.attachments[id]
				draft.attachments = append(draft.attachments[:index], draft.attachments[index+1:]...)
				delete(compose.attachments, id)
				c.updateComposeUsage(compose)
			case C.REMOVE_DETACHMENT:
				compose := c.composes[event.i]
				draft := compose.draft
				id := binary.LittleEndian.Uint64(event.data)
				index := compose.detachments[id]
				draft.detachments = append(draft.detachments[:index], draft.detachments[index+1:]...)
				delete(compose.detachments, id)
				c.updateComposeUsage(compose)
			case C.COMPOSE_TEXT:
				compose := c.composes[event.i]
				compose.draft.body = string(event.data)
				c.updateComposeUsage(compose)
			case C.COMPOSE_CLOSE:
				delete(c.composes, event.i)
			}
		case newMessage := <-c.newMessageChan:
			c.processNewMessage(newMessage)
		case msr := <-c.messageSentChan:
			if msr.id != 0 {
				c.processMessageSent(msr)
			}
		case update := <-c.pandaChan:
			c.processPANDAUpdate(update)
		case event := <-c.backgroundChan:
			switch event := event.(type) {
			case DetachmentError:
				compose := backgroundTasks[event.id]
				if compose == nil {
					continue
				}
				c.sendCocoaCommand(cocoaCommand{cmd: C.DETACHMENT_ERROR, i: compose.id, s: marshalCocoaData(struct {
					Msg string
				}{
					event.err.Error(),
				})})
				delete(backgroundTasks, event.id)
				compose.pendingDetachmentsCancel = nil
			case DetachmentProgress:
				compose := backgroundTasks[event.id]
				if compose == nil {
					continue
				}
				c.sendCocoaCommand(cocoaCommand{cmd: C.DETACHMENT_UPDATE, i: compose.id, s: marshalCocoaData(struct {
					Done, Total uint64
					Status      string
				}{
					event.done,
					event.total,
					event.status,
				})})
			case DetachmentComplete:
				compose := backgroundTasks[event.id]
				if compose == nil {
					continue
				}
				draft := compose.draft
				compose.detachments[event.id] = len(draft.detachments)
				draft.detachments = append(draft.detachments, event.detachment)
				c.sendCocoaCommand(cocoaCommand{cmd: C.ADD_DETACHMENT, i: compose.id, s: marshalCocoaData(struct {
					Label string
					Id    uint64
				}{
					Label: fmt.Sprintf("%s (decryption key)", event.detachment.GetFilename()),
					Id:    event.id,
				})})
				c.updateComposeUsage(compose)
			}
		case <-c.log.updateChan:
			/*case <-c.timerChan:
			c.processTimer(currentMsgId)
			return */
		}
	}
}

func (c *cocoaClient) processFetch(msg *InboxMessage)                 {}
func (c *cocoaClient) processServerAnnounce(announce *InboxMessage)   {}
func (c *cocoaClient) processAcknowledgement(ackedMsg *queuedMessage) {}
func (c *cocoaClient) processRevocationOfUs(by *Contact)              {}
func (c *cocoaClient) processRevocation(by *Contact)                  {}
func (c *cocoaClient) processMessageDelivered(msg *queuedMessage)     {}
func (c *cocoaClient) processPANDAUpdateUI(update pandaUpdate)        {}
func (c *cocoaClient) removeInboxMessageUI(msg *InboxMessage)         {}
func (c *cocoaClient) removeOutboxMessageUI(msg *queuedMessage)       {}
func (c *cocoaClient) addRevocationMessageUI(msg *queuedMessage)      {}
func (c *cocoaClient) removeContactUI(contact *Contact)               {}
func (c *cocoaClient) logEventUI(contact *Contact, event Event)       {}

var globalClient *cocoaClient

func NewCocoaClient(stateFilename string, rand io.Reader, testing, autoFetch bool) *cocoaClient {
	fds, _ := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	syscall.SetNonblock(fds[0], true)

	c := &cocoaClient{
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
			backgroundChan:     make(chan interface{}, 32),
			pandaChan:          make(chan pandaUpdate, 1),
			signingRequestChan: make(chan signingRequest),
			usedIds:            make(map[uint64]bool),
		},

		signalReadFD:  fds[0],
		signalWriteFD: fds[1],
		actions:       make(chan cocoaCommand, 16),
		events:        make(chan cocoaEvent, 16),
		composes:      make(map[uint64]*activeCompose),
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

	globalClient = c
	return c
}

func (c *cocoaClient) Start() {
	go func() {
		c.loadUI()
	}()

	C.RunGUI(C.int(c.signalReadFD))
}
