// +build !darwin

package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/go.crypto/ssh/terminal"
	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/pond/client/disk"
	"github.com/agl/pond/client/system"
	"github.com/agl/pond/panda"
	pond "github.com/agl/pond/protos"
)

type cliClient struct {
	client

	term        *terminal.Terminal
	termWrapper *terminalWrapper
	input       *cliInput
	interrupt   chan bool
	// cliIdsAssigned contains cliIds that have been used in the current
	// session to avoid giving the same cliId to two different objects.
	cliIdsAssigned map[cliId]bool

	// currentObj is either a *Draft or *InboxMessage and is the object
	// that the user is currently interacting with.
	currentObj interface{}
}

func (c *cliClient) Printf(format string, args ...interface{}) {
	c.term.Write([]byte(fmt.Sprintf(format, args...)))
}

func (c *cliClient) newCliId() cliId {
	var buf [2]byte

	for {
		c.randBytes(buf[:])
		v := (cliId(buf[0])&0x7f)<<8 | cliId(buf[1])
		if v == invalidCliId {
			continue
		}
		if _, ok := c.cliIdsAssigned[v]; !ok {
			c.cliIdsAssigned[v] = true
			return v
		}
	}

	panic("unreachable")
}

func terminalEscape(s string, lineBreaksOk bool) string {
	in := []byte(s)
	var out []byte

	for _, b := range in {
		switch {
		case b == '\t':
			out = append(out, ' ')
		case b == '\r':
			continue
		case b == '\n' && lineBreaksOk:
			out = append(out, '\n')
		case b < 32:
			out = append(out, '?')
		default:
			out = append(out, b)
		}
	}

	return string(out)
}

func (c *cliClient) Start() {
	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err.Error())
	}
	defer terminal.Restore(0, oldState)

	wrapper, interruptChan := NewTerminalWrapper(os.Stdin)
	c.interrupt = interruptChan
	c.termWrapper = wrapper

	c.term = terminal.NewTerminal(wrapper, "> ")
	if width, height, err := terminal.GetSize(0); err == nil {
		c.term.SetSize(width, height)
	}

	c.loadUI()

	if c.writerChan != nil {
		c.save()
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

type terminalWrapper struct {
	io.Writer
	sync.Mutex

	err   error
	chars bytes.Buffer
	cond  *sync.Cond

	// pauseOnEnter determines whether the goroutine waits on restartChan
	// after reading a newline. This is to allow a subprocess to take the
	// terminal.
	pauseOnEnter bool
	// restartChan is used to signal to the goroutine that it's ok to start
	// reading from the terminal again because we aren't going to be
	// spawning a subprocess that needs the terminal.
	restartChan chan bool
	// waitingToRestart is true if the goroutine is waiting on restartChan.
	waitingToRestart bool
}

func NewTerminalWrapper(term io.ReadWriter) (*terminalWrapper, chan bool) {
	wrapper := &terminalWrapper{
		Writer:      term,
		restartChan: make(chan bool, 1),
	}
	wrapper.cond = sync.NewCond(&wrapper.Mutex)

	c := make(chan bool, 1)
	go wrapper.run(term, c)
	return wrapper, c
}

func (wrapper *terminalWrapper) PauseOnEnter() {
	wrapper.Lock()
	defer wrapper.Unlock()

	wrapper.pauseOnEnter = true
}

func (wrapper *terminalWrapper) Restart() {
	wrapper.Lock()
	defer wrapper.Unlock()

	if wrapper.waitingToRestart {
		wrapper.restartChan <- true
		wrapper.waitingToRestart = false
	}
}

func (wrapper *terminalWrapper) Read(buf []byte) (int, error) {
	wrapper.Lock()
	defer wrapper.Unlock()

	for wrapper.chars.Len() == 0 && wrapper.err == nil {
		if wrapper.waitingToRestart {
			wrapper.waitingToRestart = false
			wrapper.restartChan <- true
		}
		wrapper.cond.Wait()
	}

	if wrapper.err != nil {
		return 0, wrapper.err
	}

	return wrapper.chars.Read(buf)
}

func (wrapper *terminalWrapper) run(r io.Reader, interruptChan chan bool) {
	var buf [1]byte
	for {
		n, err := r.Read(buf[:])

		// Check for Ctrl-C.
		if err == nil && n == 1 && buf[0] == 3 {
			select {
			case interruptChan <- true:
				break
			default:
			}
			err = errInterrupted
		}

		wrapper.Lock()
		if err != nil {
			wrapper.err = err
		} else {
			wrapper.chars.Write(buf[:n])
		}

		if err == nil && n == 1 && buf[0] == '\r' && wrapper.pauseOnEnter {
			wrapper.waitingToRestart = true
			wrapper.cond.Signal()
			wrapper.Unlock()
			<-wrapper.restartChan
		} else {
			wrapper.cond.Signal()
			wrapper.Unlock()
		}
	}
}

const (
	termCol1   = "\x1b[38;5;129m"
	termCol2   = "\x1b[38;5;135m"
	termCol3   = "\x1b[38;5;141m"
	termPrefix = termCol1 + ">" + termCol2 + ">" + termCol3 + ">" + termReset

	termWarnCol1   = "\x1b[38;5;196m"
	termWarnCol2   = "\x1b[38;5;202m"
	termWarnCol3   = "\x1b[38;5;208m"
	termWarnPrefix = termWarnCol1 + ">" + termWarnCol2 + ">" + termWarnCol3 + ">" + termReset

	termErrCol1   = "\x1b[38;5;160m"
	termErrCol2   = "\x1b[38;5;160m"
	termErrCol3   = "\x1b[38;5;160m"
	termErrPrefix = termErrCol1 + ">" + termErrCol2 + ">" + termErrCol3 + ">" + termReset

	termInfoCol1   = "\x1b[38;5;021m"
	termInfoCol2   = "\x1b[38;5;027m"
	termInfoCol3   = "\x1b[38;5;033m"
	termInfoPrefix = termInfoCol1 + ">" + termInfoCol2 + ">" + termInfoCol3 + ">" + termReset

	termHeaderPrefix = "  " + termInfoCol3 + "-" + termReset

	termCliIdStart = "\x1b[38;5;045m"

	termReset = "\x1b[0m"
)

func (c *cliClient) initUI() {
	c.Printf("%s Pond...\n", termPrefix)
}

func (c *cliClient) loadingUI() {
}

func (c *cliClient) drawChevrons(phase int) int {
	phase = (phase + 1) % 3
	cols := []string{termCol1, termCol2, termCol3}

	var line []byte
	for i := range cols {
		i := (i - phase) % 3
		if i < 0 {
			i += 3
		}
		line = append(line, cols[i]...)
		line = append(line, '>')
	}
	line = append(line, "\x1b[3D\x1b[0m"...)
	c.term.Write(line)

	return phase
}

func (c *cliClient) torPromptUI() error {
	banner := "Please start a Tor SOCKS listener on port 9050 or 9150..."
	bannerLength := 4 + len(banner)
	c.Printf("%s %s", termPrefix, banner)

	phase := 0
	animateTicker := time.NewTicker(250 * time.Millisecond)
	defer animateTicker.Stop()
	probeTicker := time.NewTicker(1 * time.Second)
	defer probeTicker.Stop()

	for {
		select {
		case <-c.interrupt:
			return errInterrupted
		case <-animateTicker.C:
			c.Printf("\x1b[%dD", bannerLength)
			phase = c.drawChevrons(phase)
			c.Printf("\x1b[%dC", bannerLength)
		case <-probeTicker.C:
			if c.detectTor() {
				return nil
			}
		}
	}

	return nil
}

func (c *cliClient) sleepUI(d time.Duration) error {
	select {
	case <-c.interrupt:
		return errInterrupted
	case <-time.After(d):
		return nil
	}

	return nil
}

func (c *cliClient) errorUI(msg string, fatal bool) {
	prefix := termWarnPrefix
	if fatal {
		prefix = termErrPrefix
	}
	c.Printf("%s %s\n", prefix, msg)
}

func (c *cliClient) ShutdownAndSuspend() error {
	return errInterrupted
}

func (c *cliClient) createPassphraseUI() (string, error) {
	c.Printf("%s %s\n", termInfoPrefix, msgCreatePassphrase)
	return c.term.ReadPassword("password> ")
}

func (c *cliClient) createErasureStorage(pw string, stateFile *disk.StateFile) error {
	c.Printf("%s %s\n", termErrPrefix, "Erasure storage not yet implemented.")
	stateFile.Erasure = nil
	return stateFile.Create(pw)
}

func (c *cliClient) createAccountUI() error {
	defaultServer := msgDefaultServer
	if c.dev {
		defaultServer = msgDefaultDevServer
	}

	c.Printf("%s %s Just hit enter to use the default server [%s]\n", termInfoPrefix, msgCreateAccount, defaultServer)
	c.term.SetPrompt("server> ")

	for {
		line, err := c.term.ReadLine()
		if err != nil {
			return err
		}
		if len(line) == 0 {
			line = defaultServer
		}
		c.server = line

		updateMsg := func(msg string) {
			c.Printf("%s %s\n", termInfoPrefix, msg)
		}

		if err := c.doCreateAccount(updateMsg); err != nil {
			c.Printf("%s %s\n", termErrPrefix, err.Error())
			continue
		}

		break
	}

	return nil
}

func (c *cliClient) keyPromptUI(stateFile *disk.StateFile) error {
	c.Printf("%s %s\n", termInfoPrefix, msgKeyPrompt)

	for {
		line, err := c.term.ReadPassword("password> ")
		if err != nil {
			return err
		}

		if err := c.loadState(stateFile, line); err != disk.BadPasswordError {
			return err
		}

		c.Printf("%s %s\n", termWarnPrefix, msgIncorrectPassword)
	}

	return nil
}

func (c *cliClient) processFetch(inboxMsg *InboxMessage) {
	if inboxMsg.message != nil && len(inboxMsg.message.Body) == 0 {
		// Skip acks.
		return
	}

	if inboxMsg.cliId == invalidCliId {
		inboxMsg.cliId = c.newCliId()
	}

	c.Printf("%s New message (%s%s%s) received from %s\n", termPrefix, termCliIdStart, inboxMsg.cliId.String(), termReset, terminalEscape(c.contacts[inboxMsg.from].name, false))
}

func (c *cliClient) processServerAnnounce(inboxMsg *InboxMessage) {
	c.Printf("%s New message received from home server\n", termPrefix)
}

func (c *cliClient) processAcknowledgement(ackedMsg *queuedMessage) {
	c.Printf("%s Message acknowledged by %s\n", termPrefix, terminalEscape(c.contacts[ackedMsg.to].name, false))
}

func (c *cliClient) processRevocationOfUs(by *Contact) {
	c.Printf("%s Access to contact revoked. All outgoing messages dropped: %s\n", termPrefix, terminalEscape(c.contacts[by.id].name, false))
}

func (c *cliClient) processRevocation(by *Contact) {
}

func (c *cliClient) processMessageDelivered(msg *queuedMessage) {
	if !msg.revocation && len(msg.message.Body) > 0 {
		c.Printf("%s Message %s%s%s to %s transmitted successfully\n", termPrefix, termCliIdStart, msg.cliId.String(), termReset, terminalEscape(c.contacts[msg.to].name, false))
	}
	c.showQueueState()
}

func (c *cliClient) setCurrentObject(o interface{}) {
	c.currentObj = o

	if c.currentObj == nil {
		c.term.SetPrompt(fmt.Sprintf("%s>%s ", termCol1, termReset))
		return
	}

	var id cliId
	switch o := c.currentObj.(type) {
	case *Draft:
		id = o.cliId
	case *InboxMessage:
		id = o.cliId
	case *Contact:
		id = o.cliId
	case *queuedMessage:
		id = o.cliId
	default:
		panic("unknown currentObj type")
	}

	c.term.SetPrompt(fmt.Sprintf("%s%s%s>%s ", termCliIdStart, id.String(), termCol1, termReset))
}

func (c *cliClient) mainUI() {
	c.term.SetPrompt(fmt.Sprintf("%s>%s ", termCol1, termReset))
	c.showState()

	termChan := make(chan cliTerminalLine)
	c.input = &cliInput{
		term: c.term,
	}
	c.termWrapper.PauseOnEnter()
	go c.input.processInput(termChan)

	for {
		select {
		case line := <-termChan:
			if line.err != nil {
				return
			}
			c.processCommand(line.command)
			close(line.ackChan)
		case newMessage := <-c.newMessageChan:
			c.processNewMessage(newMessage)
		case msr := <-c.messageSentChan:
			if msr.id != 0 {
				c.processMessageSent(msr)
			}
		/*case update := <-c.pandaChan:
		c.processPANDAUpdate(update) */
		case <-c.backgroundChan:
		case <-c.log.updateChan:
		}
	}
}

func (c *cliClient) showState() {
	if len(c.inbox) > 0 {
		c.Printf("%s Inbox:\n", termPrefix)
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
		if msg.cliId == invalidCliId {
			msg.cliId = c.newCliId()
		}

		c.Printf(" %s %s : %s (%s%s%s)\n", i.Star(), terminalEscape(fromString, false), subline, termCliIdStart, msg.cliId.String(), termReset)
	}

	if len(c.outbox) > 0 {
		c.Printf("\n%s Outbox:\n", termPrefix)
	}
	for _, msg := range c.outbox {
		if msg.revocation {
			c.Printf(" %s Revocation : %s\n", msg.indicator().Star(), msg.created.Format(shortTimeFormat))
			continue
		}
		if len(msg.message.Body) > 0 {
			if msg.cliId == invalidCliId {
				msg.cliId = c.newCliId()
			}

			subline := msg.created.Format(shortTimeFormat)
			c.Printf(" %s %s : %s (%s%s%s)\n", msg.indicator().Star(), terminalEscape(c.contacts[msg.to].name, false), subline, termCliIdStart, msg.cliId.String(), termReset)
		}
	}

	if len(c.drafts) > 0 {
		c.Printf("\n%s Drafts:\n", termPrefix)
	}
	for _, msg := range c.drafts {
		if msg.cliId == invalidCliId {
			msg.cliId = c.newCliId()
		}

		subline := msg.created.Format(shortTimeFormat)
		c.Printf("   %s : %s (%s%s%s)\n", terminalEscape(c.contacts[msg.to].name, false), subline, termCliIdStart, msg.cliId.String(), termReset)
	}

	if len(c.contacts) > 0 {
		c.Printf("\n%s Contacts:\n", termPrefix)
	}
	for _, contact := range c.contacts {
		if contact.cliId == invalidCliId {
			contact.cliId = c.newCliId()
		}
		c.Printf("   %s %s (%s%s%s)\n", terminalEscape(contact.name, false), contact.subline(), termCliIdStart, contact.cliId.String(), termReset)
	}

	c.showQueueState()
}

func (c *cliClient) showQueueState() {
	c.queueMutex.Lock()
	queueLength := len(c.queue)
	c.queueMutex.Unlock()
	switch {
	case queueLength > 1:
		c.Printf("%s There are %d messages waiting to be transmitted\n", termInfoPrefix, queueLength)
	case queueLength > 0:
		c.Printf("%s There is one message waiting to be transmitted\n", termInfoPrefix)
	default:
		c.Printf("%s There are no messages waiting to be transmitted\n", termInfoPrefix)
	}
}

func (c *cliClient) printDraftSize(draft *Draft) {
	usageString, oversize := draft.usageString()
	prefix := termPrefix
	if oversize {
		prefix = termErrPrefix
	}
	c.Printf("%s Message using %s\n", prefix, usageString)
}

func (c *cliClient) processCommand(cmd interface{}) {
	// First commands that might start a subprocess that needs terminal
	// control.
	switch cmd.(type) {
	case composeCommand:
		if contact, ok := c.currentObj.(*Contact); ok {
			c.compose(contact, nil, nil)
			return
		}
		c.Printf("%s Select contact first\n", termWarnPrefix)
	case editCommand:
		if draft, ok := c.currentObj.(*Draft); ok {
			c.compose(nil, draft, nil)
			return
		}
		c.Printf("%s Select draft first\n", termWarnPrefix)
	}

	// The command won't need to start subprocesses with terminal control
	// so we can start watching for Ctrl-C again.
	c.termWrapper.Restart()

	switch cmd := cmd.(type) {
	case tagCommand:
		if len(cmd.tag) == 0 {
			c.showState()
			return
		}
		cliId, ok := cliIdFromString(cmd.tag)
		if !ok {
			c.Printf("%s Bad tag\n", termWarnPrefix)
			return
		}
		for _, msg := range c.inbox {
			if msg.cliId == cliId {
				c.setCurrentObject(msg)
				return
			}
		}
		for _, msg := range c.outbox {
			if msg.cliId == cliId {
				c.setCurrentObject(msg)
				return
			}
		}
		for _, msg := range c.drafts {
			if msg.cliId == cliId {
				c.setCurrentObject(msg)
				return
			}
		}
		for _, contact := range c.contacts {
			if contact.cliId == cliId {
				c.setCurrentObject(contact)
				return
			}
		}
		c.Printf("%s Unknown tag\n", termWarnPrefix)
	case deleteCommand:
		if c.currentObj == nil {
			c.Printf("%s Select object first\n", termWarnPrefix)
			return
		}
		switch o := c.currentObj.(type) {
		case *Draft:
			delete(c.drafts, o.id)
			c.save()
			c.setCurrentObject(nil)
		default:
			c.Printf("%s Cannot delete current object\n", termWarnPrefix)
		}
	case sendCommand:
		draft, ok := c.currentObj.(*Draft)
		if !ok {
			c.Printf("%s Select draft first\n", termWarnPrefix)
		}
		to := c.contacts[draft.to]
		var myNextDH []byte
		if to.ratchet == nil {
			var nextDHPub [32]byte
			curve25519.ScalarBaseMult(&nextDHPub, &to.currentDHPrivate)
			myNextDH = nextDHPub[:]
		}

		if len(draft.body) == 0 {
			// Zero length bodies are ACKs.
			draft.body = " "
		}
		id := c.randId()
		err := c.send(to, &pond.Message{
			Id:               proto.Uint64(id),
			Time:             proto.Int64(c.Now().Unix()),
			Body:             []byte(draft.body),
			BodyEncoding:     pond.Message_RAW.Enum(),
			InReplyTo:        proto.Uint64(draft.inReplyTo),
			MyNextDh:         myNextDH,
			Files:            draft.attachments,
			DetachedFiles:    draft.detachments,
			SupportedVersion: proto.Int32(protoVersion),
		})
		if err != nil {
			c.log.Errorf("%s Error sending: %s\n", termErrPrefix, err)
			return
		}
		if draft.inReplyTo != 0 {
			for _, msg := range c.inbox {
				if msg.id == draft.inReplyTo {
					msg.acked = true
					break
				}
			}
		}
		delete(c.drafts, draft.id)
		c.setCurrentObject(nil)
		for _, msg := range c.outbox {
			if msg.id == id {
				if msg.cliId == invalidCliId {
					msg.cliId = c.newCliId()
				}
				c.Printf("%s Created new outbox entry %s%s%s\n", termInfoPrefix, termCliIdStart, msg.cliId.String(), termReset)
				c.setCurrentObject(msg)
				c.showQueueState()
				break
			}
		}
		c.save()
	case ackCommand:
		msg, ok := c.currentObj.(*InboxMessage)
		if !ok {
			c.Printf("%s Select inbox message first\n", termWarnPrefix)
			return
		}
		if msg.acked {
			c.Printf("%s Message has already been acknowledged\n", termWarnPrefix)
			return
		}
		msg.acked = true
		c.sendAck(msg)
		c.showQueueState()
	case showCommand:
		if c.currentObj == nil {
			c.Printf("Select object first\n")
		}
		switch o := c.currentObj.(type) {
		case *queuedMessage:
			c.showOutbox(o)
		case *InboxMessage:
			c.showInbox(o)
		case *Draft:
			c.showDraft(o)
		}
	case attachCommand:
		draft, ok := c.currentObj.(*Draft)
		if !ok {
			c.Printf("%s Select draft first\n", termWarnPrefix)
		}
		contents, size, err := openAttachment(cmd.Filename)
		if err != nil {
			c.Printf("%s Failed to open file: %s\n", termErrPrefix, terminalEscape(err.Error(), false))
			return
		}
		if size > 0 {
			c.Printf("%s File is too large (%d bytes) to attach. Use the 'upload' or 'save-encrypted' commands to encrypt the file, include just the keys in the message and either upload or save the ciphertext", termErrPrefix, size)
			return
		}

		base := filepath.Base(cmd.Filename)
		a := &pond.Message_Attachment{
			Filename: proto.String(base),
			Contents: contents,
		}
		draft.attachments = append(draft.attachments, a)
		c.Printf("%s Attached '%s' (%d bytes)\n", termPrefix, terminalEscape(base, false), len(contents))
		c.printDraftSize(draft)

	default:
		panic(fmt.Sprintf("Unhandled command: %#v", cmd))
	}
}

func (c *cliClient) compose(to *Contact, draft *Draft, inReplyTo *InboxMessage) {
	if draft == nil {
		draft = &Draft{
			id:      c.randId(),
			created: time.Now(),
			to:      to.id,
			cliId:   c.newCliId(),
		}
		if inReplyTo != nil {
			draft.inReplyTo = inReplyTo.id
		}
		c.Printf("%s Created new draft: %s%s%s\n", termInfoPrefix, termCliIdStart, draft.cliId.String(), termReset)
		c.drafts[draft.id] = draft
		c.setCurrentObject(draft)
	}
	if to == nil {
		to = c.contacts[draft.to]
	}

	editor := os.Getenv("EDITOR")
	if len(editor) == 0 {
		editor = "vi"
	}

	tempDir, err := system.SafeTempDir()
	if err != nil {
		c.Printf("%s Failed to get safe temp directory: %s\n", termErrPrefix, err)
		return
	}

	tempFile, err := ioutil.TempFile(tempDir, "pond-cli-")
	if err != nil {
		c.Printf("%s Failed to create temp file: %s\n", termErrPrefix, err)
		return
	}
	tempFileName := tempFile.Name()
	defer func() {
		os.Remove(tempFileName)
	}()

	fmt.Fprintf(tempFile, "# Pond message. Lines prior to the first blank line are ignored.\nTo: %s\n\n", to.name)
	tempFile.WriteString(draft.body)

	cmd := exec.Command(editor, tempFileName)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		c.Printf("%s Failed to run editor: %s\n", termErrPrefix, err)
		return
	}
	tempFile.Close()
	tempFile, err = os.Open(tempFileName)
	if err != nil {
		c.Printf("%s Failed to open temp file: %s\n", termErrPrefix, err)
		return
	}
	contents, err := ioutil.ReadAll(tempFile)
	if err != nil {
		c.Printf("%s Failed to read temp file: %s\n", termErrPrefix, err)
		return
	}

	if i := bytes.Index(contents, []byte("\n\n")); i >= 0 {
		contents = contents[i+2:]
	}
	draft.body = string(contents)
	c.printDraftSize(draft)

	c.save()
}

func (c *cliClient) showInbox(msg *InboxMessage) {
	isServerAnnounce := msg.from == 0
	fromString, sentTimeText, eraseTimeText, msgText := msg.Strings()
	msg.read = true

	var contact *Contact
	if !isServerAnnounce {
		contact = c.contacts[msg.from]
	}
	if len(fromString) == 0 && contact != nil {
		fromString = contact.name
	}

	c.Printf("%s From: %s\n", termHeaderPrefix, terminalEscape(fromString, false))
	c.Printf("%s Sent: %s\n", termHeaderPrefix, sentTimeText)
	c.Printf("%s Erase: %s\n", termHeaderPrefix, eraseTimeText)
	c.Printf("%s Retain: %t\n\n", termHeaderPrefix, msg.retained)
	c.term.Write([]byte(terminalEscape(string(msgText), true /* line breaks ok */)))
}

func (c *cliClient) showOutbox(msg *queuedMessage) {
	contact := c.contacts[msg.to]
	var sentTime string
	if contact.revokedUs {
		sentTime = "(never - contact has revoked us)"
	} else {
		sentTime = formatTime(msg.sent)
	}
	eraseTime := formatTime(msg.created.Add(messageLifetime))

	c.Printf("%s To: %s\n", termHeaderPrefix, terminalEscape(contact.name, false))
	c.Printf("%s Created: %s\n", termHeaderPrefix, formatTime(time.Unix(*msg.message.Time, 0)))
	c.Printf("%s Sent: %s\n", termHeaderPrefix, sentTime)
	c.Printf("%s Acknowledged: %s\n", termHeaderPrefix, formatTime(msg.acked))
	c.Printf("%s Erase: %s\n\n", termHeaderPrefix, eraseTime)
	c.term.Write([]byte(terminalEscape(string(msg.message.Body), true /* line breaks ok */)))
}

func (c *cliClient) showDraft(msg *Draft) {
	contact := c.contacts[msg.to]
	c.Printf("%s To: %s\n", termHeaderPrefix, terminalEscape(contact.name, false))
	c.Printf("%s Created: %s\n", termHeaderPrefix, formatTime(msg.created))
	c.term.Write([]byte(terminalEscape(string(msg.body), true /* line breaks ok */)))
}

func NewCLIClient(stateFilename string, rand io.Reader, testing, autoFetch bool) *cliClient {
	c := &cliClient{
		client: client{
			testing:         testing,
			dev:             testing,
			autoFetch:       autoFetch,
			stateFilename:   stateFilename,
			log:             NewLog(),
			rand:            rand,
			contacts:        make(map[uint64]*Contact),
			drafts:          make(map[uint64]*Draft),
			newMessageChan:  make(chan NewMessage),
			messageSentChan: make(chan messageSendResult, 1),
			backgroundChan:  make(chan interface{}, 8),
			pandaChan:       make(chan pandaUpdate, 1),
			usedIds:         make(map[uint64]bool),
		},
		cliIdsAssigned: make(map[cliId]bool),
	}
	c.ui = c

	c.newMeetingPlace = func() panda.MeetingPlace {
		return &panda.HTTPMeetingPlace{
			TorAddress: c.torAddress,
			URL:        "https://panda-key-exchange.appspot.com/exchange",
		}
	}
	c.log.toStderr = false
	return c
}
