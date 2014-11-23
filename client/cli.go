package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
	"strings"

	"code.google.com/p/go.crypto/ssh/terminal"
	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/pond/client/disk"
	"github.com/agl/pond/client/system"
	"github.com/agl/pond/panda"
	pond "github.com/agl/pond/protos"
)

const haveCLI = true

const (
	tpmIntroMsg      = "It's very difficult to erase information on modern computers so Pond tries to use the TPM chip if possible."
	tpmPresentMsg    = "Your computer appears to have a TPM chip. You'll need tcsd (the TPM daemon) running in order to use it."
	tpmNotPresentMsg = "Your computer does not appear to have a TPM chip. Without one, it's possible that someone in physical possession of your computer and passphrase could extract old messages that should have been deleted. Using a computer with a TPM is strongly preferable until alternatives can be implemented."
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

	// deleteArmed is set to true after an attempt to delete a contact. The
	// first attempt sets this flag, the second will actually delete a
	// contact. This flag is cleared after any command that is not a delete
	// command.
	deleteArmed bool

	// currentObj is either a *Draft or *InboxMessage and is the object
	// that the user is currently interacting with.
	currentObj interface{}
}

func (c *cliClient) Printf(format string, args ...interface{}) {
	c.term.Write([]byte(fmt.Sprintf(format, args...)))
}

func (c *cliClient) clearTerminalMessage(length int) {
	if length > 0 {
		c.term.Write([]byte(fmt.Sprintf("\x1b[%dD\x1b[2K", length)))
	}
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

func updateTerminalSize(term *terminal.Terminal) {
	width, height, err := terminal.GetSize(0)
	if err != nil {
		return
	}
	term.SetSize(width, height)
}

func (c *cliClient) Start() {
	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		panic(err.Error())
	}
	defer terminal.Restore(0, oldState)

	signal.Notify(make(chan os.Signal), os.Interrupt)

	wrapper, interruptChan := NewTerminalWrapper(os.Stdin)
	wrapper.SetErrorOnInterrupt(true)
	c.interrupt = interruptChan
	c.termWrapper = wrapper

	c.term = terminal.NewTerminal(wrapper, "> ")
	updateTerminalSize(c.term)

	resizeChan := make(chan os.Signal)
	go func() {
		for _ = range resizeChan {
			updateTerminalSize(c.term)
		}
	}()
	signal.Notify(resizeChan, syscall.SIGWINCH)

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
	// errorOnInterrupt, if true, causes reading from the terminal to
	// result in errInterrupted if Ctrl-C is pressed.
	errorOnInterrupt bool
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

func (wrapper *terminalWrapper) SetErrorOnInterrupt(on bool) {
	wrapper.Lock()
	defer wrapper.Unlock()

	wrapper.errorOnInterrupt = true
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
			wrapper.Lock()
			errorOnInterrupt := wrapper.errorOnInterrupt
			wrapper.Unlock()
			if errorOnInterrupt {
				err = errInterrupted
			} else {
				continue
			}
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
		if err != nil {
			break
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

	termGray = "\x1b[38;5;250m"

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

	for {
		pw1, err := c.term.ReadPassword("passphrase> ")
		if err != nil {
			return "", err
		}
		if len(pw1) == 0 {
			return "", nil
		}
		c.Printf("%s Please confirm by entering the same passphrase again\n", termInfoPrefix)
		pw2, err := c.term.ReadPassword("passphrase> ")
		if err != nil {
			return "", err
		}
		if pw1 == pw2 {
			return pw1, nil
		}
		c.Printf("%s Passphrases don't match. Please start over\n", termInfoPrefix)
	}
	return "", nil
}

func (c *cliClient) createAccountUI(stateFile *disk.StateFile, pw string) (bool, error) {
	defaultServer := msgDefaultServer
	if c.dev {
		defaultServer = msgDefaultDevServer
	}

	c.Printf("%s %s\n", termInfoPrefix, msgCreateAccount)
	c.Printf("%s\n", termInfoPrefix)
	c.Printf("%s Either leave this blank to use the default server, enter a pondserver:// address, or type one of the following server nicknames:\n", termInfoPrefix)
	for _, server := range knownServers {
		if len(server.nickname) == 0 {
			continue
		}
		c.Printf("%s   %s: %s\n", termInfoPrefix, server.nickname, server.description)
	}
	c.term.SetPrompt("server> ")

	for {
		line, err := c.term.ReadLine()
		if err != nil {
			return false, err
		}
		for _, server := range knownServers {
			if line == server.nickname {
				line = server.uri
				break
			}
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

	return false, nil
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

	c.Printf("\x07%s (%s) New message (%s%s%s) received from %s\n", termPrefix, time.Now().Format(shortTimeFormat), termCliIdStart, inboxMsg.cliId.String(), termReset, terminalEscape(c.ContactName(inboxMsg.from), false))
}

func (c *cliClient) processServerAnnounce(inboxMsg *InboxMessage) {
	c.Printf("%s New message received from home server\n", termPrefix)
}

func (c *cliClient) processAcknowledgement(ackedMsg *queuedMessage) {
	c.Printf("%s (%s) Message acknowledged by %s\n", termPrefix, time.Now().Format(shortTimeFormat), terminalEscape(c.ContactName(ackedMsg.to), false))
}

func (c *cliClient) processRevocationOfUs(by *Contact) {
	c.Printf("%s Access to contact revoked. All outgoing messages dropped: %s\n", termPrefix, terminalEscape(c.ContactName(by.id), false))
}

func (c *cliClient) processRevocation(by *Contact) {
}

// unsealPendingMessages is run once a key exchange with a contact has
// completed and unseals any previously unreadable messages from that contact.
func (c *cliClient) unsealPendingMessages(contact *Contact) {
	var needToFilter bool

	for _, msg := range c.inbox {
		if msg.message == nil && msg.from == contact.id {
			if !c.unsealMessage(msg, contact) {
				needToFilter = true
				continue
			}
			if len(msg.message.Body) == 0 {
				needToFilter = true
				continue
			}
		}
	}

	if needToFilter {
		c.dropSealedAndAckMessagesFrom(contact)
	}
}

func (c *cliClient) processPANDAUpdateUI(update pandaUpdate) {
	contact := c.contacts[update.id]

	switch {
	case update.err != nil:
		c.Printf("%s Key exchange with %s failed: %s\n", termErrPrefix, terminalEscape(contact.name, false), terminalEscape(update.err.Error(), false))
	case update.serialised != nil:
	case update.result != nil:
		c.Printf("%s Key exchange with %s complete\n", termPrefix, terminalEscape(contact.name, false))
		c.unsealPendingMessages(contact)
	}
}

func (c *cliClient) processMessageDelivered(msg *queuedMessage) {
	if !msg.revocation && len(msg.message.Body) > 0 {
		c.Printf("%s (%s) Message %s%s%s to %s transmitted successfully\n", termPrefix, time.Now().Format(shortTimeFormat), termCliIdStart, msg.cliId.String(), termReset, terminalEscape(c.ContactName(msg.to), false))
	}
	c.showQueueState()
}

func (c *cliClient) removeInboxMessageUI(msg *InboxMessage) {
}

func (c *cliClient) removeOutboxMessageUI(msg *queuedMessage) {
}

func (c *cliClient) addRevocationMessageUI(msg *queuedMessage) {
	c.Printf("%s New revocation message created and pending transmission to home server.\n", termPrefix)
}

func (c *cliClient) removeContactUI(contact *Contact) {
}

func (c *cliClient) logEventUI(contact *Contact, event Event) {
	c.Printf("%s While processing message from %s: %s\n", termWarnPrefix, terminalEscape(contact.name, false), terminalEscape(event.msg, false))
}

func (c *cliClient) setCurrentObject(o interface{}) {
	c.currentObj = o

	if c.currentObj == nil {
		c.term.SetPrompt(fmt.Sprintf("%s>%s ", termCol1, termReset))
		return
	}

	var id cliId
	var typ string
	switch o := c.currentObj.(type) {
	case *Draft:
		typ = "draft"
		id = o.cliId
	case *InboxMessage:
		typ = "inbox"
		id = o.cliId
	case *Contact:
		typ = "contact"
		id = o.cliId
	case *queuedMessage:
		typ = "outbox"
		id = o.cliId
	default:
		panic("unknown currentObj type")
	}

	c.term.SetPrompt(fmt.Sprintf("%s%s%s/%s%s%s>%s ", termGray, typ, termReset, termCliIdStart, id.String(), termCol1, termReset))
}

func (c *cliClient) mainUI() {
	c.term.SetPrompt(fmt.Sprintf("%s>%s ", termCol1, termReset))
	c.showState()

	termChan := make(chan cliTerminalLine)
	c.input = &cliInput{
		term: c.term,
	}
	c.termWrapper.PauseOnEnter()
	c.termWrapper.SetErrorOnInterrupt(false)
	go c.input.processInput(termChan)

	for {
		select {
		case sigReq := <-c.signingRequestChan:
			c.processSigningRequest(sigReq)
		case line := <-termChan:
			if line.err != nil {
				return
			}

		FlushInterrupts:
			for {
				select {
				case <-c.interrupt:
					continue
				default:
					break FlushInterrupts
				}
			}

			shouldQuit := c.processCommand(line.command)
			// Any command other than a delete command clears the
			// delete confirmation flag.
			if _, ok := line.command.(deleteCommand); !ok {
				c.deleteArmed = false
			}
			if shouldQuit {
				return
			}
			close(line.ackChan)
		case newMessage := <-c.newMessageChan:
			c.processNewMessage(newMessage)
		case msr := <-c.messageSentChan:
			if msr.id != 0 {
				c.processMessageSent(msr)
			}
		case update := <-c.pandaChan:
			c.processPANDAUpdate(update)
		case <-c.backgroundChan:
		case <-c.log.updateChan:
		}
	}
}

// cliTable is a structure for containing tabular data for display on the
// terminal. For example, the inbox, outbox etc summaries are handled using
// this structure.
type cliTable struct {
	// heading is an optional string that will be printed before the table.
	heading string
	rows    []cliRow
	// noIndicators, if true, causes the indicators for each row to be
	// ignored and a blue hyphen to be printed in their place.
	noIndicators bool
	// noTrailingNewline, if true, stops the printing of a newline after
	// the table.
	noTrailingNewline bool
}

// cliRow is a row of terminal data.
type cliRow struct {
	// indicator contains an optional indicator star to print at the
	// beginning of the line.
	indicator Indicator
	// cols contains strings for each column. Note that strings must
	// already have been terminal escaped.
	cols []string
	// id contains an optional tag string to print as a final column.
	id cliId
}

// UpdateWidths calculates the maximum width of each column. If widths is
// non-nil then those widths are updated.
func (tab cliTable) UpdateWidths(widths []int) []int {
	if len(tab.rows) == 0 {
		return widths
	}

	n := len(tab.rows[0].cols)
	if len(widths) < n {
		newWidths := make([]int, n)
		copy(newWidths, widths)
		widths = newWidths
	}

	for _, row := range tab.rows {
		if len(row.cols) != n {
			panic("table is not square")
		}
		for j, col := range row.cols {
			if widths[j] < len(col) {
				widths[j] = len(col)
			}
		}
	}

	return widths
}

// WriteTo writes the terminal data for tab to w.
func (tab cliTable) WriteTo(w io.Writer) {
	widths := tab.UpdateWidths(nil)
	tab.WriteToWithWidths(w, widths)
}

// WriteToWithWidths writes the terminal data for tab to w using the given
// widths.
func (tab cliTable) WriteToWithWidths(w io.Writer, widths []int) {
	maxWidth := 0
	for _, width := range widths {
		if maxWidth < width {
			maxWidth = width
		}
	}

	spaces := make([]byte, maxWidth+1)
	for i := range spaces {
		spaces[i] = ' '
	}

	buf := bufio.NewWriter(w)

	if len(tab.heading) > 0 {
		buf.WriteString(termInfoPrefix)
		buf.WriteString(" ")
		buf.WriteString(tab.heading)
		buf.WriteString("\n")
	}

	for _, row := range tab.rows {
		if tab.noIndicators {
			buf.WriteString(termHeaderPrefix)
		} else {
			buf.WriteString(" ")
			buf.WriteString(row.indicator.Star())
		}
		buf.WriteString(" ")

		for j, width := range widths {
			var col string
			if j < len(row.cols) {
				col = row.cols[j]
			}

			switch j {
			case 0:
			case 1:
				buf.WriteString(" ")
				if len(col) > 0 {
					buf.WriteString(termGray)
					buf.WriteString("|")
					buf.WriteString(termReset)
				} else {
					buf.WriteString(" ")
				}
				buf.WriteString(" ")
			default:
				buf.WriteString(" ")
			}
			buf.WriteString(col)
			buf.Write(spaces[:width-len(col)])
		}

		if row.id != invalidCliId {
			buf.WriteString(" (")
			buf.WriteString(termCliIdStart)
			buf.WriteString(row.id.String())
			buf.WriteString(termReset)
			buf.WriteString(")")
		}
		buf.WriteString("\n")
	}

	if len(tab.rows) > 0 && !tab.noTrailingNewline {
		buf.WriteString("\n")
	}
	buf.Flush()
}

func (c *cliClient) showState() {
	tables := make([]cliTable, 0, 4)

	tables = append(tables, c.outboxSummary())
	tables = append(tables, c.inboxSummary())
	tables = append(tables, c.draftsSummary())
	tables = append(tables, c.contactsSummary())

	var widths []int
	for _, table := range tables {
		widths = table.UpdateWidths(widths)
	}

	for _, table := range tables {
		table.WriteToWithWidths(c.term, widths)
	}

	c.showQueueState()
}

func (c *cliClient) showIdentity() {
	table := cliTable{
		noIndicators: true,
		heading:      "Identity",
		rows: []cliRow{
			cliRow{cols: []string{"Server", terminalEscape(c.server, false)}},
			cliRow{cols: []string{"Public identity", fmt.Sprintf("%x", c.identityPublic[:])}},
			cliRow{cols: []string{"Public key", fmt.Sprintf("%x", c.pub[:])}},
			cliRow{cols: []string{"State file", terminalEscape(c.stateFilename, false)}},
			cliRow{cols: []string{"Group generation", fmt.Sprintf("%d", c.generation)}},
		},
	}
	table.WriteTo(c.term)
}

func (c *cliClient) inboxSummary() (table cliTable) {
	if len(c.inbox) == 0 {
		return
	}

	heading := "Inbox"
	var filter uint64

	if obj, isContact := c.currentObj.(*Contact); isContact {
		heading = "Inbox messages from " + terminalEscape(obj.name, false)
		filter = obj.id
	}

	table = cliTable{
		heading: heading,
		rows:    make([]cliRow, 0, len(c.inbox)),
	}

	for _, msg := range c.inbox {
		if filter != 0 && filter != msg.from {
			continue
		}

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
			} else if !msg.acked && msg.from != 0 {
				i = indicatorYellow
			}
			subline = time.Unix(*msg.message.Time, 0).Format(shortTimeFormat)
		}
		if msg.cliId == invalidCliId {
			msg.cliId = c.newCliId()
		}

		table.rows = append(table.rows, cliRow{
			i,
			[]string{
				terminalEscape(c.ContactName(msg.from), false),
				subline,
			},
			msg.cliId,
		})
	}

	return
}

func (c *cliClient) outboxSummary() (table cliTable) {
	if len(c.outbox) == 0 {
		return
	}

	heading := "Outbox"
	var filter uint64

	if obj, isContact := c.currentObj.(*Contact); isContact {
		heading = "Outbox messages to " + terminalEscape(obj.name, false)
		filter = obj.id
	}

	table = cliTable{
		heading: heading,
		rows:    make([]cliRow, 0, len(c.outbox)),
	}

	for _, msg := range c.outbox {
		if filter != 0 && filter != msg.to {
			continue
		}

		subline := msg.created.Format(shortTimeFormat)

		if msg.revocation {
			table.rows = append(table.rows, cliRow{
				msg.indicator(nil),
				[]string{
					"(Revocation)",
					subline,
				},
				invalidCliId,
			})
			continue
		}

		if len(msg.message.Body) == 0 {
			continue
		}

		if msg.cliId == invalidCliId {
			msg.cliId = c.newCliId()
		}

		to := c.contacts[msg.to]
		table.rows = append(table.rows, cliRow{
			msg.indicator(to),
			[]string{
				terminalEscape(to.name, false),
				subline,
			},
			msg.cliId,
		})
	}

	return
}

func (c *client) listDraftRecipients(draft *Draft,nobody string) string {
	if len(draft.toNormal) == 0 && len(draft.toIntroduce) == 0 { return nobody }
	return c.listContactsAndUnknowns(append(draft.toNormal,draft.toIntroduce...))
}

func (c *cliClient) draftsSummary() (table cliTable) {
	if len(c.drafts) == 0 {
		return
	}

	heading := "Drafts"
	var filter uint64

	if obj, isContact := c.currentObj.(*Contact); isContact {
		heading = "Draft messages to " + terminalEscape(obj.name, false)
		filter = obj.id
	}

	table = cliTable{
		heading: heading,
		rows:    make([]cliRow, 0, len(c.drafts)),
	}

	for _, draft := range c.drafts {
		if filter != 0 && !isInIdSet(draft.toNormal,filter) && !isInIdSet(draft.toIntroduce,filter) {
			continue
		}

		if draft.cliId == invalidCliId {
			draft.cliId = c.newCliId()
		}

		subline := draft.created.Format(shortTimeFormat)
		toName := c.listDraftRecipients(draft,"(nobody)")

		table.rows = append(table.rows, cliRow{
			indicatorNone,
			[]string{
				terminalEscape(toName, false),
				subline,
			},
			draft.cliId,
		})
	}

	return
}

func (c *cliClient) contactsSummaryRaw(title string,
			filter func (*Contact) bool) (table cliTable) {
	if len(c.contacts) == 0 {
		return
	}

	table = cliTable{
		heading: title,
		rows:    make([]cliRow, 0, len(c.contacts)),
	}

	contacts := c.client.contactsSorted()

	for _, contact := range contacts {
		if ! filter(contact) { continue }
		if contact.cliId == invalidCliId {
			contact.cliId = c.newCliId()
		}
		indicator := indicatorNone
		if contact.revokedUs {
			indicator = indicatorBlack
		}

		table.rows = append(table.rows, cliRow{
			indicator,
			[]string{
				terminalEscape(contact.name, false),
				contact.subline(),
			},
			contact.cliId,
		})
	}

	return
}

func (c *cliClient) contactsSummary() (cliTable) {
	return c.contactsSummaryRaw("Contacts",func (c *Contact) bool { return true })
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

// prepareSubobjectCommand performs the initial processing for a command that
// operates on a subobject of a message. (Either an attachment or a
// detachment.) It takes the 1-based index string from the user and the number
// and name of the subobjects in question. It return the validated, 0-based
// index.
func (c *cliClient) prepareSubobjectCommand(userIndex string, n int, objName string) (i int, ok bool) {
	i, err := strconv.Atoi(userIndex)
	if err != nil {
		c.Printf("%s Failed to parse number: %s\n", termErrPrefix, terminalEscape(err.Error(), false))
		return
	}
	i-- // the UI has 1-based indexing
	switch {
	case i < 0:
		c.Printf("%s Invalid %s number\n", termErrPrefix, objName)
	case i < n:
		ok = true
	default:
		c.Printf("%s There aren't that many %ss\n", termErrPrefix, objName)
	}
	return
}

// runBackgroundProcess processes update messages from a background process and
// displays them.
func (c *cliClient) runBackgroundProcess(id uint64, cancelThunk func()) (*pond.Message_Detachment, bool) {
	lastProgressStringLength := 0

	for {
		select {
		case event := <-c.backgroundChan:
			switch e := event.(type) {
			case DetachmentError:
				if e.id != id {
					continue
				}
				c.clearTerminalMessage(lastProgressStringLength)
				lastProgressStringLength = 0
				c.Printf("%s Error: %s\n", termErrPrefix, terminalEscape(e.err.Error(), false))
				return nil, false
			case DetachmentProgress:
				if e.id != id {
					continue
				}
				s := fmt.Sprintf("%s: %d / %d", terminalEscape(e.status, false), e.done, e.total)
				c.clearTerminalMessage(lastProgressStringLength)
				lastProgressStringLength = len(s)
				c.term.Write([]byte(s))
			case DetachmentComplete:
				if e.id != id {
					continue
				}
				c.clearTerminalMessage(lastProgressStringLength)
				c.Printf("%s Complete\n", termPrefix)
				return e.detachment, true
			}
		case <-c.interrupt:
			cancelThunk()
			c.clearTerminalMessage(lastProgressStringLength)
			c.Printf("%s Aborted\n", termPrefix)
			return nil, false
		}
	}
	return nil, false
}

func (c *cliClient) processCommand(cmd interface{}) (shouldQuit bool) {
	// First commands that might start a subprocess that needs terminal
	// control.
	switch cmd.(type) {
	case composeCommand:
		if contact, ok := c.currentObj.(*Contact); ok {
			c.compose(c.newDraftCLI([]uint64{contact.id}, nil, nil))
		} else {
			c.Printf("%s Select contact first\n", termWarnPrefix)
		}

	case editCommand:
		if draft, ok := c.currentObj.(*Draft); ok {
			if len(draft.toNormal) < 1 {
				c.Printf("%s Draft was created in the GUI and doesn't have a destination specified. Please use the GUI to manipulate this draft.\n", termErrPrefix)
				return
			}
			if len(draft.toNormal) > 1 || len(draft.toIntroduce) > 1 {
				c.Printf("%s Draft was created in the GUI and has multiple destinations specified. Please use the GUI to manipulate this draft.\n", termErrPrefix)
				return
			}
			c.compose(draft)
		} else {
			c.Printf("%s Select draft first\n", termWarnPrefix)
		}

	case replyCommand:
		msg, ok := c.currentObj.(*InboxMessage)
		if !ok {
			c.Printf("%s Select inbox message first\n", termWarnPrefix)
			return
		}
		if msg.from == 0 {
			c.Printf("%s Cannot reply to server announcement\n", termWarnPrefix)
			return
		}
		c.compose(c.newDraftCLI([]uint64{msg.from}, nil, msg))

	default:
		goto Handle
	}
	return

Handle:
	// The command won't need to start subprocesses with terminal control
	// so we can start watching for Ctrl-C again.
	c.termWrapper.Restart()

	switch cmd := cmd.(type) {
	case clearCommand:
		c.Printf("\x1b[2J")

	case helpCommand:
		if cmd.ShowAll {
			c.input.showHelp(0, true)
			return
		}

		switch c.currentObj.(type) {
		case *Contact:
			c.input.showHelp(contextContact, false)
		case *Draft:
			c.input.showHelp(contextDraft, false)
		case *InboxMessage:
			c.input.showHelp(contextInbox, false)
		case *queuedMessage:
			c.input.showHelp(contextOutbox, false)
		default:
			c.input.showHelp(0, false)
		}

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

	case logCommand:
		n := 15
		if l := len(c.log.entries); l < n {
			n = l
		}
		table := cliTable{
			rows:         make([]cliRow, 0, n),
			noIndicators: true,
		}

		for _, entry := range c.log.entries[len(c.log.entries)-n:] {
			table.rows = append(table.rows, cliRow{
				cols: []string{
					entry.Format(logTimeFormat),
					terminalEscape(entry.s, false),
				},
			})
		}

		table.WriteTo(c.term)

	case transactNowCommand:
		c.Printf("%s Triggering immediate network transaction.\n", termPrefix)
		select {
		case c.fetchNowChan <- nil:
		default:
		}

	case closeCommand:
		c.setCurrentObject(nil)

	case quitCommand:
		c.ShutdownAndSuspend()
		c.Printf("Goodbye!\n")
		shouldQuit = true
		return

	case deleteCommand:
		if c.currentObj == nil {
			c.Printf("%s Select object first\n", termWarnPrefix)
			return
		}
		if !c.deleteArmed {
			switch obj := c.currentObj.(type) {
			case *Contact:
				c.Printf("%s You attempted to delete a contact (%s). Doing so removes all messages to and from that contact and revokes their ability to send you messages. To confirm, enter the delete command again.\n", termWarnPrefix, terminalEscape(obj.name, false))
			case *Draft:
				toName := ""
				if len(obj.toNormal) > 0 || len(obj.toIntroduce) > 0 {
					toName = " to " + c.listContactsAndUnknowns(append(obj.toNormal,obj.toIntroduce...))
				}
				c.Printf("%s You attempted to delete a draft message%s. To confirm, enter the delete command again.\n", termWarnPrefix, terminalEscape(toName, false))
			case *queuedMessage:
				c.queueMutex.Lock()
				if c.indexOfQueuedMessage(obj) != -1 {
					c.queueMutex.Unlock()
					c.Printf("%s Please abort the unsent message before deleting it.\n", termErrPrefix)
					return
				}
				c.queueMutex.Unlock()
				c.Printf("%s You attempted to delete a message (to %s). To confirm, enter the delete command again.\n", termWarnPrefix, terminalEscape(c.ContactName(obj.to), false))
			case *InboxMessage:
				c.Printf("%s You attempted to delete a message (from %s). To confirm, enter the delete command again.\n", termWarnPrefix, terminalEscape(c.ContactName(obj.from), false))
			default:
				c.Printf("%s Cannot delete current object\n", termWarnPrefix)
				return
			}
			c.deleteArmed = true
			return
		}
		c.deleteArmed = false

		switch obj := c.currentObj.(type) {
		case *Contact:
			c.deleteContact(obj)
		case *Draft:
			delete(c.drafts, obj.id)
		case *queuedMessage:
			c.deleteOutboxMsg(obj.id)
		case *InboxMessage:
			c.deleteInboxMsg(obj.id)
		default:
			c.Printf("%s Cannot delete current object\n", termWarnPrefix)
			return
		}
		c.setCurrentObject(nil)
		c.save()

	case sendCommand:
		draft, ok := c.currentObj.(*Draft)
		if !ok {
			c.Printf("%s Select draft first\n", termWarnPrefix)
			return
		}
		if len(draft.toNormal) == 0 && len(draft.toIntroduce) == 0 {
			c.Printf("%s Draft was created in the GUI and doesn't have a destination specified. Please use the GUI to manipulate this draft.\n", termErrPrefix)
			return
		}
		messages, err := c.sendDraft(draft)
		if err != nil {
			c.Printf("%s Error sending: %s\n", termErrPrefix, err)
		}
		if draft.inReplyTo != 0 {
			for _, msg := range c.inbox {
				if msg.message != nil && msg.message.GetId() == draft.inReplyTo {
					msg.acked = true
					break
				}
			}
		}
		delete(c.drafts, draft.id)
		c.setCurrentObject(nil)
		// We previously ranged over c.outbox compairing ids here, but it's safe
		// to assume messages contains pointers to the actual outbox messages.
		for _, msg := range messages {
			if msg.cliId == invalidCliId {
				msg.cliId = c.newCliId()
			}
			c.Printf("%s Created new outbox entry %s%s%s\n", termInfoPrefix, termCliIdStart, msg.cliId.String(), termReset)
			if len(messages) == 1 {
				c.setCurrentObject(msg)
			}
		}
				c.showQueueState()
		c.save()

	case abortCommand:
		msg, ok := c.currentObj.(*queuedMessage)
		if !ok {
			c.Printf("%s Select outbox message first\n", termErrPrefix)
			return
		}

		c.queueMutex.Lock()
		index := c.indexOfQueuedMessage(msg)
		if index == -1 || msg.sending {
			c.queueMutex.Unlock()
			c.Printf("%s Too Late to Abort!\n", termErrPrefix)
			return
		}

		c.removeQueuedMessage(index)
		c.queueMutex.Unlock()

		c.deleteOutboxMsg(msg.id)
		draft := c.outboxToDraft(msg)
		c.drafts[draft.id] = draft
		if draft.cliId == invalidCliId {
			draft.cliId = c.newCliId()
		}

		c.Printf("%s Aborted sending %s%s%s and moved to Drafts as %s%s%s\n", termInfoPrefix, termCliIdStart, msg.cliId.String(), termReset, termCliIdStart, draft.cliId.String(), termReset)
		c.save()
		c.setCurrentObject(draft)

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
		if msg.from == 0 {
			c.Printf("%s Cannot ack server announcement\n", termWarnPrefix)
			return
		}
		msg.acked = true
		c.sendAck(msg)
		c.showQueueState()

	case showCommand:
		if c.currentObj == nil {
			c.Printf("Select object first\n")
			return
		}
		switch o := c.currentObj.(type) {
		case *queuedMessage:
			c.showOutbox(o)
		case *InboxMessage:
			c.showInbox(o)
		case *Draft:
			c.showDraft(o)
		case *Contact:
			c.showContact(o)
		default:
			c.Printf("%s Cannot show the current object\n", termWarnPrefix)
		}

	case showIdentityCommand:
		c.showIdentity()

	case showInboxSummaryCommand:
		c.inboxSummary().WriteTo(c.term)

	case showOutboxSummaryCommand:
		c.outboxSummary().WriteTo(c.term)

	case showDraftsSummaryCommand:
		c.draftsSummary().WriteTo(c.term)

	case showContactsCommand:
		c.contactsSummary().WriteTo(c.term)

	case showQueueStateCommand:
		c.showQueueState()

	case statusCommand:
		c.showState()

	case attachCommand:
		draft, ok := c.currentObj.(*Draft)
		if !ok {
			c.Printf("%s Select draft first\n", termWarnPrefix)
			return
		}
		contents, size, err := openAttachment(cmd.Filename)
		if err != nil {
			c.Printf("%s Failed to open file: %s\n", termErrPrefix, terminalEscape(err.Error(), false))
			return
		}
		if size > 0 {
			c.Printf("%s File is too large (%d bytes) to attach. Use the 'upload' command to encrypt the file and upload it to your home server. Pond will include the key in the current draft.\n", termErrPrefix, size)
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

	case uploadCommand:
		draft, ok := c.currentObj.(*Draft)
		if !ok {
			c.Printf("%s Select draft first\n", termWarnPrefix)
			return
		}

		base := filepath.Base(cmd.Filename)
		id := c.randId()
		c.Printf("%s Padding, encrypting and uploading '%s' to home server (Ctrl-C to abort):\n", termPrefix, terminalEscape(base, false))
		cancelThunk := c.startUpload(id, cmd.Filename)

		if detachment, ok := c.runBackgroundProcess(id, cancelThunk); ok {
			draft.detachments = append(draft.detachments, detachment)
		}

	case downloadCommand:
		msg, ok := c.currentObj.(*InboxMessage)
		if !ok {
			c.Printf("%s Select inbox message\n", termWarnPrefix)
			return
		}
		i, ok := c.prepareSubobjectCommand(cmd.Number, len(msg.message.DetachedFiles), "detachment")
		if !ok {
			return
		}
		id := c.randId()

		if msg.message.DetachedFiles[i].Url == nil {
			c.Printf("%s That detachment is just a key; you need to obtain the encrypted payload out-of-band. Use the save-key command and the decrypt utility the decrypt the payload.\n", termErrPrefix)
			return
		}

		c.Printf("%s Downloading and decrypting detachment (Ctrl-C to abort):\n", termPrefix)
		cancelThunk := c.startDownload(id, cmd.Filename, msg.message.DetachedFiles[i])

		c.runBackgroundProcess(id, cancelThunk)

	case saveKeyCommand:
		msg, ok := c.currentObj.(*InboxMessage)
		if !ok {
			c.Printf("%s Select inbox message\n", termWarnPrefix)
			return
		}
		i, ok := c.prepareSubobjectCommand(cmd.Number, len(msg.message.DetachedFiles), "detachment")
		if !ok {
			return
		}

		if msg.message.DetachedFiles[i].Url != nil {
			c.Printf("%s (Note that this detachment can be downloaded with the 'download' command)\n", termInfoPrefix)
		}

		bytes, err := proto.Marshal(msg.message.DetachedFiles[i])
		if err != nil {
			panic(err)
		}

		if err := ioutil.WriteFile(cmd.Filename, bytes, 0600); err != nil {
			c.Printf("%s Failed to write file: %s\n", termErrPrefix, terminalEscape(err.Error(), false))
		} else {
			c.Printf("%s Wrote file\n", termPrefix)
		}

	case saveCommand:
		msg, ok := c.currentObj.(*InboxMessage)
		if !ok {
			c.Printf("%s Select inbox message\n", termWarnPrefix)
			return
		}
		i, ok := c.prepareSubobjectCommand(cmd.Number, len(msg.message.Files), "attachment")
		if !ok {
			return
		}

		if err := ioutil.WriteFile(cmd.Filename, msg.message.Files[i].GetContents(), 0600); err != nil {
			c.Printf("%s Failed to write file: %s\n", termErrPrefix, terminalEscape(err.Error(), false))
		} else {
			c.Printf("%s Wrote file\n", termPrefix)
		}

	case removeCommand:
		draft, ok := c.currentObj.(*Draft)
		if !ok {
			c.Printf("%s Select draft first\n", termWarnPrefix)
			return
		}
		i, ok := c.prepareSubobjectCommand(cmd.Number, len(draft.attachments)+len(draft.detachments), "attachment")
		if !ok {
			return
		}

		if i < len(draft.attachments) {
			draft.attachments = append(draft.attachments[:i], draft.attachments[i+1:]...)
			return
		}
		i -= len(draft.attachments)
		draft.detachments = append(draft.detachments[:i], draft.detachments[i+1:]...)

	case newContactCommand:
		for _, contact := range c.contacts {
			if contact.name == cmd.Name {
				c.Printf("%s A contact with that name already exists.\n", termErrPrefix)
				return
			}
		}

		var sharedSecret string

		for {
			c.Printf("Enter shared secret with contact, or hit enter to generate, print and use a random one\n")
			var err error
			sharedSecret, err = c.term.ReadPassword("secret: ")
			if err != nil {
				panic(err)
			}
			if len(sharedSecret) == 0 || panda.IsAcceptableSecretString(sharedSecret) {
				break
			}
			c.Printf("%s Checksum incorrect. Please try again.\n", termErrPrefix)
		}

		if len(sharedSecret) == 0 {
			sharedSecret = panda.NewSecretString(c.rand)
			c.Printf("%s Shared secret: %s\n", termPrefix, sharedSecret)
		}

		contact := &Contact{
			name:      cmd.Name,
			isPending: true,
			id:        c.randId(),
			cliId:     c.newCliId(),
		}

		stack := &panda.CardStack{
			NumDecks: 1,
		}
		secret := panda.SharedSecret{
			Secret: sharedSecret,
			Cards:  *stack,
		}

		c.newKeyExchange(contact)
		c.beginPandaKeyExchange(contact,secret)
		c.Printf("%s Key exchange running in background.\n", termPrefix)

	case renameCommand:
		if contact, ok := c.currentObj.(*Contact); ok {
			c.renameContact(contact, cmd.NewName)
		} else {
			c.Printf("%s Select contact first\n", termWarnPrefix)
		}

	case introduceContactCommand:
		contact, ok := c.currentObj.(*Contact)
		if !ok {
			c.Printf("%s Select contact first\n", termWarnPrefix)
			return
		}

		cl := c.inputContactList("Introduce " + contact.name + " to contacts : ",
			func (cnt *Contact) bool { return ! cnt.isPending && contact.id != cnt.id }  )
		if len(cl) == 0 { return }
		cl = append(contactList{contact},cl...)

		// Build from notes eventually
		prebody0 := "To: " + cl[1].name
		for _, to := range cl[2:] {
			prebody0 += ", " + to.name
		}
		prebody0 += "\n\n"
		body0, ok := c.inputTextBlock(prebody0,true)
		if !ok { c.Printf("Not OK, what now?") }
		bodyn, ok := c.inputTextBlock("To: " + cl[0].name + "\n\n",true)
		if !ok { c.Printf("Not OK, what now?") }

		// c.introduceContact_onemany(contact,cl)
		urls := c.introducePandaMessages_onemany(cl,true)
		for i := range cl {
			draft := c.newDraft([]uint64{cl[i].id},nil,nil)
			draft.cliId = c.newCliId()
			if i == 0 {
				draft.body = body0
			}	else {
				draft.body = bodyn 
			}
			draft.body += introducePandaMessageDesc + urls[i]
			c.sendDraft(draft)
			c.Printf("%s Sending introduction message %s%s%s to %s\n", termInfoPrefix,
				termCliIdStart, draft.cliId.String(), termReset, cl[i].name)
		}
		c.save()

	case introduceContactGroupCommand:
		cl := c.inputContactList("Introduce contacts to one another.",
			func (cnt *Contact) bool { return ! cnt.isPending }  )
		if len(cl) == 0 { return }

		prebody := "To: " + cl[1].name
		for _, to := range cl[2:] {
			prebody += ", " + to.name
		}
		prebody += "\n\n"
		body, ok := c.inputTextBlock(prebody,true)
		if !ok { c.Printf("Not OK, what now?") }

		urls := c.introducePandaMessages_group(cl,true)
		for i := range cl {
			draft := c.newDraft([]uint64{cl[i].id},nil,nil)
			draft.cliId = c.newCliId()
			draft.body = body + introducePandaMessageDesc + urls[i]
			c.sendDraft(draft)
			c.Printf("%s Sending introduction message %s%s%s to %s\n", termInfoPrefix,
				termCliIdStart, draft.cliId.String(), termReset, cl[i].name)
		}
		c.save()

	case greetContactCommand:
		msg, ok := c.currentObj.(*InboxMessage)
		if !ok {
			c.Printf("%s Select inbox message first\n", termWarnPrefix)
			return
		}

		pcs := c.parsePandaURLs(msg.from,string(msg.message.Body))
		for i, pc := range pcs {
			if cmd.Index == "*" || cmd.Index == pc.name || 
			   cmd.Index == fmt.Sprintf("%d",i) {
				   if pc.id != 0 {
					   c.Printf("%s Introduced contact %s is your existing contact %s\n", termPrefix,pc.name,c.contacts[pc.id].name)
					   return
				   }
				   c.Printf("%s Begining PANDA key exchange with %s\n", termPrefix,pc.name)
				   c.beginProposedPandaKeyExchange(pc,msg.from);
				   if cmd.Index != "*" { return } 
			}
		}

	case retainCommand:
		msg, ok := c.currentObj.(*InboxMessage)
		if !ok {
			c.Printf("%s Select inbox message first\n", termWarnPrefix)
			return
		}
		msg.retained = true
		c.save()

	case dontRetainCommand:
		msg, ok := c.currentObj.(*InboxMessage)
		if !ok {
			c.Printf("%s Select inbox message first\n", termWarnPrefix)
			return
		}
		msg.retained = false
		msg.exposureTime = c.Now()
		// TODO: the CLI needs to expire messages when open as the GUI
		// does. See guiClient.processTimer.
		c.save()

	default:
		panic(fmt.Sprintf("Unhandled command: %#v", cmd))
	}

	return
}

func (c *cliClient) inputTextBlock(draft string,isMessage bool) (body string, ok bool) {
	ok = false
	predraft := map[bool]string{
		true: "# Pond message. Lines prior to the first blank line are ignored.\n",
		false: "",
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

	if len(draft) == 0 {
		draft = "\n"
	} 
	fmt.Fprintf(tempFile, predraft[isMessage] + draft)

	// The editor is forced to vim because I'm not sure about leaks from
	// other editors. (I'm not sure about leaks from vim either, but at
	// least I can set some arguments to remove the obvious ones.)
	cmd := exec.Command("vim", "-n", "--cmd", "set modelines=0", "-c", "set viminfo=", "+4", "--", tempFileName)
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

	if isMessage {
		if i := bytes.Index(contents, []byte("\n\n")); i >= 0 {
			contents = contents[i+2:]
		}
	}
	body = string(contents)
	ok = true
	return
}

func (c *client) newDraft(toNormal, toIntroduce []uint64, inReplyTo *InboxMessage) (*Draft) {
	// Any recipients specified now overide inReplyTo.from, no panic.
	draft := &Draft{
		id:          c.randId(),
		created:     time.Now(),
		toNormal:    toNormal,
		toIntroduce: toIntroduce,
	}
	if inReplyTo != nil && inReplyTo.message != nil {
		draft.inReplyTo = inReplyTo.message.GetId()
		draft.body = indentForReply(inReplyTo.message.GetBody())
		if len(toNormal) == 0 && len(toIntroduce) == 0 && inReplyTo.from != 0 {
			toNormal = []uint64{inReplyTo.from}
		}
	}
	c.drafts[draft.id] = draft
	return draft
}

func (c *cliClient) newDraftCLI(toNormal, toIntroduce []uint64, inReplyTo *InboxMessage) (*Draft) {
	draft := c.newDraft(toNormal,toIntroduce,inReplyTo)
	draft.cliId = c.newCliId()
	c.Printf("%s Created new draft: %s%s%s\n", termInfoPrefix, termCliIdStart, draft.cliId.String(), termReset)
	c.setCurrentObject(draft)
	return draft
}

func (c *cliClient) compose(draft *Draft) {
	if draft == nil {
		c.Printf("%s Internal error, compose nolonger initializes drafts.\n", termErrPrefix)
	}

	body0 := ""
	funTo := func(title string,tos []uint64) bool {
		if len(tos) == 0 { return true }
		body0 += title + c.listContactsAndUnknowns(tos) + "\n"
		// TODO : Allow writing messages to pending contacts, issue warning here
		for _,to := range tos {
			if c.contacts[to].isPending {
				c.Printf("%s Cannot send message to pending contact %s.\n", termErrPrefix, c.contacts[to].name)
				return false
			}
		}
		return true
	}
	if ! funTo("Introdiucing: ",draft.toIntroduce) ||
	   ! funTo("To: ",draft.toNormal)  { return }

	body, ok := c.inputTextBlock(body0 + "\n" + draft.body,true)
	if ! ok { return }
	draft.body = body
	c.printDraftSize(draft)
	c.save()
}

func (c *cliClient) showInbox(msg *InboxMessage) {
	sentTimeText, eraseTimeText, msgText := msg.Strings()
	msg.read = true

	table := cliTable{
		noIndicators:      true,
		noTrailingNewline: true,
		rows: []cliRow{
			cliRow{cols: []string{"From", terminalEscape(c.ContactName(msg.from), false)}},
			cliRow{cols: []string{"Sent", sentTimeText}},
			cliRow{cols: []string{"Erase", eraseTimeText}},
			cliRow{cols: []string{"Retain", fmt.Sprintf("%t", msg.retained)}},
		},
	}
	table.WriteTo(c.term)

	if msg.message != nil {
		if len(msg.message.Files) > 0 {
			c.Printf("%s Attachments (use 'save <#> <filename>' to save):\n", termHeaderPrefix)
		}
		for i, attachment := range msg.message.Files {
			c.Printf("%s     %d: %s (%d bytes):\n", termHeaderPrefix, i+1, terminalEscape(attachment.GetFilename(), false), len(attachment.Contents))
		}
		if len(msg.message.DetachedFiles) > 0 {
			c.Printf("%s Detachments (use '[download|save-key] <#> <filename>' to save):\n", termHeaderPrefix)
		}
		for i, detachment := range msg.message.DetachedFiles {
			disposition := ""
			if detachment.Url != nil {
				disposition = ", downloadable"
			}
			c.Printf("%s     %d: %s (%d bytes%s):\n", termHeaderPrefix, i+1, terminalEscape(detachment.GetFilename(), false), detachment.GetSize(), disposition)
		}
	}
	c.Printf("\n")
	c.term.Write([]byte(terminalEscape(string(msgText), true /* line breaks ok */)))
	c.Printf("\n")

	pcs := c.parsePandaURLs(msg.from,string(msg.message.Body))
	if len(pcs) > 0 {
		c.Printf("%s Introduced contacts.  Add with greet command.\n", termPrefix)
	}
	for i, pc := range pcs {
		s := ""
		if pc.id != 0 { 
			s0 := "exists"
			s1 := ""
			if c.contacts[pc.id].isPending {
				s0 = "pending";
			}
			if c.contacts[pc.id].name != pc.name {
				s1 += "as " + c.contacts[pc.id].name
			}
			s = fmt.Sprintf("(%s%s)",s0,s1) 
		}
		c.Printf("%d. %s %s\n",i,pc.name,s)
	}
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

	table := cliTable{
		noIndicators: true,
		rows: []cliRow{
			cliRow{cols: []string{"To", terminalEscape(contact.name, false)}},
			cliRow{cols: []string{"Created", formatTime(time.Unix(*msg.message.Time, 0))}},
			cliRow{cols: []string{"Sent", sentTime}},
			cliRow{cols: []string{"Acknowledged", formatTime(msg.acked)}},
			cliRow{cols: []string{"Erase", eraseTime}},
		},
	}
	table.WriteTo(c.term)

	if len(msg.message.Files) > 0 {
		c.Printf("%s Attachments:\n", termHeaderPrefix)
	}
	for _, attachment := range msg.message.Files {
		c.Printf("%s     %s (%d bytes):\n", termHeaderPrefix, terminalEscape(attachment.GetFilename(), false), len(attachment.Contents))
	}
	if len(msg.message.DetachedFiles) > 0 {
		c.Printf("%s Detachments:\n", termHeaderPrefix)
	}
	for _, detachment := range msg.message.DetachedFiles {
		c.Printf("%s     %s (%d bytes):\n", termHeaderPrefix, terminalEscape(detachment.GetFilename(), false), detachment.GetSize())
	}
	if len(msg.message.Files) > 0 || len(msg.message.DetachedFiles) > 0 {
		c.Printf("\n")
	}

	c.term.Write([]byte(terminalEscape(string(msg.message.Body), true /* line breaks ok */)))
	c.Printf("\n")
}

func (c *cliClient) showDraft(draft *Draft) {
	toLine := ""
	if len(draft.toIntroduce) > 0 {
		toLine = fmt.Sprintf("%s Introdiucing: %s\n", termHeaderPrefix, 
			terminalEscape(c.listContactsAndUnknowns(draft.toIntroduce), false))
	}
	if len(draft.toNormal) > 0 {
		also := ""
		if len(toLine) > 0 { also = "Also " }
		toLine += fmt.Sprintf("%s %sTo: %s\n", termHeaderPrefix, also, 
			terminalEscape(c.listContactsAndUnknowns(draft.toNormal), false))
	}
	if len(toLine) == 0 {
		toLine = fmt.Sprintf("%s To: %s\n", termHeaderPrefix, "(not specified)")
	}
	c.Printf(toLine)

	c.Printf("%s Created: %s\n", termHeaderPrefix, formatTime(draft.created))
	if len(draft.attachments) > 0 {
		c.Printf("%s Attachments (use 'remove <#>' to remove):\n", termHeaderPrefix)
	}
	for i, attachment := range draft.attachments {
		c.Printf("%s     %d: %s (%d bytes):\n", termHeaderPrefix, i+1, terminalEscape(attachment.GetFilename(), false), len(attachment.Contents))
	}
	if len(draft.detachments) > 0 {
		c.Printf("%s Detachments (use 'remove <#>' to remove):\n", termHeaderPrefix)
	}
	for i, detachment := range draft.detachments {
		c.Printf("%s     %d: %s (%d bytes):\n", termHeaderPrefix, 1+len(draft.attachments)+i, terminalEscape(detachment.GetFilename(), false), detachment.GetSize())
	}
	c.Printf("\n")
	c.term.Write([]byte(terminalEscape(string(draft.body), true /* line breaks ok */)))
	c.Printf("\n")
}

func (c *cliClient) renameContact(contact *Contact, newName string) {
	if contact.name == newName {
		return
	}

	for _, contact := range c.contacts {
		if contact.name == newName {
			c.Printf("%s Another contact already has that name.\n", termErrPrefix)
			return
		}
	}

	contact.name = newName
	c.save()
}

func (c *cliClient) inputContactList(title string,
			filter func (*Contact) bool) (cl contactList) {
	c.contactsSummaryRaw(title,filter).WriteTo(c.term)

	var prefix string = ""
	for {
		c.term.SetPrompt(prefix + "contacts> ")
		line, err := c.term.ReadLine()
		if err != nil {
			cl = nil // Empty an array with garbage cllection 
			return
		}
		xs := strings.Fields(line)
		if len(xs) <= 0 { return }
		for _, x := range xs {
			id, ok := cliIdFromString(x)
			if !ok {
				c.Printf("%s Bad contact tag %s.\n", termWarnPrefix, x)
				if len(cl) == 0 { return }
				continue
			}
			contact := c.cliIdToContact(id)
			if contact == nil {
				c.Printf("%s Tag %s is not a contact.\n", termWarnPrefix, x)
				if len(xs) != 1 && len(cl) == 0 { return }
				continue
			}
			if ! filter(contact) {
				c.Printf("%s Contact %s not allowed\n", termErrPrefix, contact.name)
				continue
			}
			c.Printf("%s Added %s \n", termPrefix, contact.name)
			cl = append(cl,contact)
		}
		if prefix == "" {
			if len(cl) > 1 { return }
			c.Printf("%s Enter a blank line when done.\n", termPrefix)
			prefix = "more "
		}
	}
}

func (c *client) listContactsAndUnknowns(ids []uint64) (string) {
	unknowns := 0
	listing := ""
	for _, id := range ids {
		cnt,ok := c.contacts[id]
		if ok {
			listing += cnt.name + ", "
		} else {
			unknowns++
		}
	}
	if unknowns > 0 {
		if len(listing) > 0 { listing += "and " }
		listing += fmt.Sprintf("%d unknown contacts.",unknowns)
	}
	listing = strings.TrimSuffix(listing,", ")
	return listing
}

func (c *cliClient) showContact(contact *Contact) {
	if len(contact.pandaResult) > 0 {
		c.Printf("%s PANDA error: %s\n", termErrPrefix, terminalEscape(contact.pandaResult, false))
	}
	if contact.revoked {
		c.Printf("%s This contact has been revoked\n", termWarnPrefix)
	}
	if contact.revokedUs {
		c.Printf("%s This contact has revoked access\n", termWarnPrefix)
	}
	if contact.isPending {
		c.Printf("%s This contact is pending\n", termWarnPrefix)
	}

	table := cliTable{
		noIndicators: true,
		rows: []cliRow{
			cliRow{cols: []string{"Name", terminalEscape(contact.name, false)}},
			cliRow{cols: []string{"Server", terminalEscape(contact.theirServer, false)}},
			cliRow{cols: []string{"Generation", fmt.Sprintf("%d", contact.generation)}},
			cliRow{cols: []string{"Public key", fmt.Sprintf("%x", contact.theirPub[:])}},
			cliRow{cols: []string{"Identity key", fmt.Sprintf("%x", contact.theirIdentityPublic[:])}},
			cliRow{cols: []string{"Client version", fmt.Sprintf("%d", contact.supportedVersion)}},
		},
	}

	if contact.introducedBy != 0 {
		cnt,ok := c.contacts[contact.introducedBy]
		name := "Unknown"
		if ok { name = terminalEscape(cnt.name,false) }
		table.rows = append(table.rows, 
			cliRow{cols: []string{"Introduced By", name }},
		)
	}
	if len(contact.verifiedBy) > 0 {
		table.rows = append(table.rows, 
			cliRow{cols: []string{"Verified By", terminalEscape(c.listContactsAndUnknowns(contact.verifiedBy), false) }},
		)
	}
	if len(contact.introducedTo) > 0 {
		table.rows = append(table.rows, 
			cliRow{cols: []string{"Introduced To", terminalEscape(c.listContactsAndUnknowns(contact.introducedTo), false) }},
		)
	}


	table.WriteTo(c.term)

	if len(contact.events) > 0 {
		table = cliTable{
			noIndicators: true,
			heading:      "Events for this contact",
		}
		for _, event := range contact.events {
			table.rows = append(table.rows,
				cliRow{cols: []string{event.t.Format(logTimeFormat), terminalEscape(event.msg, false)}},
			)
		}

		table.WriteTo(c.term)
	}
}

func NewCLIClient(stateFilename string, rand io.Reader, testing, autoFetch bool) *cliClient {
	c := &cliClient{
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
			usedIds:            make(map[uint64]bool),
			signingRequestChan: make(chan signingRequest),
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
