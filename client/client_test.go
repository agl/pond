package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"code.google.com/p/goprotobuf/proto"
	panda "github.com/agl/pond/panda"
	pond "github.com/agl/pond/protos"
)

// clientLogToStderr controls whether the TestClients will log to stderr during
// the test. This produces too much noise to be enabled all the time, but it
// can be helpful when debugging.
const clientLogToStderr = false

// Since t.Log calls don't result in any output until the test terminates, this
// constant can be tweaked to enable logging to stderr.
const debugDeadlock = false

const parallel = true

// logActions causes all GUI events to be written to the test log.
const logActions = false

type TestServer struct {
	cmd      *exec.Cmd
	port     int
	identity string
	stateDir string
}

func NewTestServer(t *testing.T) (*TestServer, error) {
	var err error
	server := new(TestServer)
	if server.stateDir, err = ioutil.TempDir("", "pond-client-test"); err != nil {
		return nil, err
	}

	// To ensure that the server dies when the test exits, we install a
	// socketpair into the child process and set a command line flag to
	// tell the server to exit if it sees EOF on that socket. Since we hold
	// the other end in this process, the kernel will close it for us if we
	// die.
	pipeFds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(pipeFds[0])
	syscall.CloseOnExec(pipeFds[1])

	serverLifeline := os.NewFile(uintptr(pipeFds[0]), "server lifeline fd")
	defer serverLifeline.Close()

	server.cmd = exec.Command("../server/server",
		"--init",
		"--base-directory", server.stateDir,
		"--port", "0",
		"--lifeline-fd", "3",
	)
	server.cmd.ExtraFiles = []*os.File{serverLifeline}
	rawStderr, err := server.cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := server.cmd.Start(); err != nil {
		return nil, err
	}

	stderr := bufio.NewReader(rawStderr)

	for {
		line, isPrefix, err := stderr.ReadLine()
		if err != nil {
			return nil, errors.New("error while reading status line: " + err.Error())
		}
		if isPrefix {
			continue
		}
		if i := bytes.Index(line, []byte("Started. Listening on port ")); i != -1 {
			line = line[i:]
			words := strings.Split(string(line), " ")
			if len(words) < 8 {
				return nil, errors.New("status line from server has unexpected form: " + string(line))
			}
			portStr := words[4]
			server.identity = words[7]

			if server.port, err = strconv.Atoi(portStr); err != nil {
				return nil, errors.New("failed to parse port number: " + err.Error())
			}
			break
		}
	}

	go func() {
		for {
			line, _, err := stderr.ReadLine()
			if err != nil {
				return
			}
			t.Logf("%s\n", string(line))
		}
	}()

	return server, nil
}

func (server *TestServer) URL() string {
	return fmt.Sprintf("pondserver://%s@127.0.0.1:%d", server.identity, server.port)
}

func (server *TestServer) Close() {
	server.cmd.Process.Kill()
	server.cmd.Wait()
	os.RemoveAll(server.stateDir)
}

type TestGUI struct {
	actions        chan interface{}
	events         chan interface{}
	signal         chan chan bool
	currentStateID int
	info           string
	t              *testing.T
	text           map[string]string
	combos         map[string][]string
	fileOpen       FileOpen
	haveFileOpen   bool
	panicOnSignal  bool
}

func NewTestGUI(t *testing.T) *TestGUI {
	return &TestGUI{
		actions:        make(chan interface{}, 16),
		events:         make(chan interface{}, 16),
		signal:         make(chan chan bool),
		currentStateID: uiStateInvalid,
		t:              t,
		text:           make(map[string]string),
		combos:         make(map[string][]string),
	}
}

func (ui *TestGUI) Actions() chan<- interface{} {
	return ui.actions
}

func (ui *TestGUI) Events() <-chan interface{} {
	return ui.events
}

func (ui *TestGUI) Signal() {
	c := make(chan bool)
	ui.signal <- c
	<-c
}

func (ui *TestGUI) Run() {
	panic("should never be called")
}

func (ui *TestGUI) processWidget(widget interface{}) {
	switch v := widget.(type) {
	case VBox:
		for _, child := range v.children {
			ui.processWidget(child)
		}
	case HBox:
		for _, child := range v.children {
			ui.processWidget(child)
		}
	case Grid:
		for _, row := range v.rows {
			for _, elem := range row {
				ui.processWidget(elem.widget)
			}
		}
	case EventBox:
		ui.processWidget(v.child)
	case Scrolled:
		ui.processWidget(v.child)
	case Frame:
		ui.processWidget(v.child)
	case TextView:
		ui.text[v.name] = v.text
	case Label:
		ui.text[v.name] = v.text
	case Combo:
		ui.combos[v.name] = v.labels
	}
}

func (ui *TestGUI) WaitForSignal() error {
	var uierr error
	ack, ok := <-ui.signal
	if !ok {
		panic("signal channel closed")
	}

ReadActions:
	for {
		select {
		case action := <-ui.actions:
			if logActions {
				ui.t.Logf("%#v", action)
			}
			if debugDeadlock {
				fmt.Printf("%#v\n", action)
			}
			switch action := action.(type) {
			case UIState:
				ui.currentStateID = action.stateID
			case UIError:
				uierr = action.err
			case UIInfo:
				ui.info = action.info
			case SetText:
				ui.text[action.name] = action.text
			case SetTextView:
				ui.text[action.name] = action.text
			case SetChild:
				ui.processWidget(action.child)
			case Append:
				for _, child := range action.children {
					ui.processWidget(child)
				}
			case InsertRow:
				for _, gride := range action.row {
					ui.processWidget(gride.widget)
				}
			case FileOpen:
				ui.fileOpen = action
				ui.haveFileOpen = true
			}
		default:
			break ReadActions
		}
	}
	ack <- true

	return uierr
}

func (ui *TestGUI) WaitForFileOpen() FileOpen {
	ui.haveFileOpen = false
	for !ui.haveFileOpen {
		if err := ui.WaitForSignal(); err != nil {
			ui.t.Fatal(err)
		}
	}
	return ui.fileOpen
}

type TestClient struct {
	*guiClient
	stateDir      string
	gui           *TestGUI
	mainUIDone    bool
	name          string
	testTimerChan chan time.Time
}

type TestClientOptions struct {
	initialStateFile string
}

func NewTestClient(t *testing.T, name string, options *TestClientOptions) (*TestClient, error) {
	tc := &TestClient{
		gui:           NewTestGUI(t),
		name:          name,
		testTimerChan: make(chan time.Time, 1),
	}
	var err error
	if tc.stateDir, err = ioutil.TempDir("", "pond-client-test"); err != nil {
		return nil, err
	}
	stateFilePath := filepath.Join(tc.stateDir, "state")
	if options != nil && len(options.initialStateFile) != 0 {
		inBytes, err := ioutil.ReadFile(options.initialStateFile)
		if err != nil {
			panic(err)
		}
		if err := ioutil.WriteFile(stateFilePath, inBytes, 0600); err != nil {
			panic(err)
		}
	}
	tc.guiClient = NewGUIClient(stateFilePath, tc.gui, rand.Reader, true, false)
	tc.guiClient.log.name = name
	tc.guiClient.log.toStderr = clientLogToStderr
	tc.guiClient.timerChan = tc.testTimerChan
	tc.guiClient.Start()
	return tc, nil
}

func (tc *TestClient) Shutdown() {
	tc.gui.t.Log("Shutting down client")
	close(tc.gui.events)

WaitForClient:
	for {
		select {
		case _, ok := <-tc.gui.actions:
			if !ok {
				break WaitForClient
			}
		case ack := <-tc.gui.signal:
			ack <- true
		}
	}
}

func (tc *TestClient) Close() {
	tc.Shutdown()
	os.RemoveAll(tc.stateDir)
}

func (tc *TestClient) AdvanceTo(state int) {
	tc.gui.currentStateID = uiStateInvalid
	for tc.gui.currentStateID != state {
		if err := tc.gui.WaitForSignal(); err != nil {
			tc.gui.t.Fatal(err)
		}
	}
}

func (tc *TestClient) Reload() {
	tc.ReloadWithMeetingPlace(nil)
}

func (tc *TestClient) ReloadWithMeetingPlace(mp panda.MeetingPlace) {
	tc.Shutdown()
	oldNowFunc := tc.nowFunc
	tc.gui = NewTestGUI(tc.gui.t)
	tc.guiClient = NewGUIClient(filepath.Join(tc.stateDir, "state"), tc.gui, rand.Reader, true /* testing */, false /* autoFetch */)
	tc.guiClient.log.name = tc.name
	tc.guiClient.log.toStderr = clientLogToStderr
	tc.guiClient.timerChan = tc.testTimerChan
	tc.nowFunc = oldNowFunc
	if mp != nil {
		tc.guiClient.newMeetingPlace = func() panda.MeetingPlace {
			return mp
		}
	}
	tc.guiClient.Start()
}

func TestOpenClose(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	client, err := NewTestClient(t, "client", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
}

func TestAccountCreation(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := NewTestClient(t, "client", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	client.gui.WaitForSignal()
	if id := client.gui.currentStateID; id != uiStateLoading {
		t.Fatalf("client in UI state %d when it was expected to be loading", id)
	}

	client.gui.WaitForSignal()
	if id := client.gui.currentStateID; id != uiStateCreatePassphrase {
		t.Fatalf("client in UI state %d when it was expected to be creating a passphrase", id)
	}
	client.gui.events <- Click{
		name:    "next",
		entries: map[string]string{"pw": ""},
	}

	client.gui.WaitForSignal()
	if id := client.gui.currentStateID; id != uiStateErasureStorage {
		t.Fatalf("client in UI state %d when it was expected to be setting up erasure storage", id)
	}

	client.gui.events <- Click{
		name: "continue",
	}

	client.gui.WaitForSignal()
	if id := client.gui.currentStateID; id != uiStateCreateAccount {
		t.Fatalf("client in UI state %d when it was expected to be creating an account", id)
	}

	client.gui.events <- Click{
		name:    "create",
		entries: map[string]string{"server": "asldfjksadfkl"},
	}
	t.Log("Waiting for error from garbage URL")
	for {
		if err := client.gui.WaitForSignal(); err != nil {
			break
		}
	}

	url := server.URL()
	client.gui.events <- Click{
		name:    "create",
		entries: map[string]string{"server": url[:len(url)-1]},
	}

	t.Log("Waiting for error from invalid port")
	for {
		if err := client.gui.WaitForSignal(); err != nil {
			break
		}
	}

	t.Log("Waiting for success")
	client.gui.events <- Click{
		name:    "create",
		entries: map[string]string{"server": url},
	}
	client.AdvanceTo(uiStateMain)
}

func proceedToMainUI(t *testing.T, client *TestClient, server *TestServer) {
	if client.mainUIDone {
		return
	}

	client.AdvanceTo(uiStateCreatePassphrase)
	client.gui.events <- Click{
		name:    "next",
		entries: map[string]string{"pw": ""},
	}
	client.AdvanceTo(uiStateErasureStorage)
	client.gui.events <- Click{
		name: "continue",
	}
	client.AdvanceTo(uiStateCreateAccount)
	url := server.URL()
	client.gui.events <- Click{
		name:    "create",
		entries: map[string]string{"server": url},
	}
	client.AdvanceTo(uiStateMain)
	client.mainUIDone = true
}

func proceedToKeyExchange(t *testing.T, client *TestClient, server *TestServer, otherName string) {
	proceedToMainUI(t, client, server)

	client.gui.events <- Click{name: "newcontact"}
	client.AdvanceTo(uiStateNewContact)

	client.gui.events <- Click{
		name:    "name",
		entries: map[string]string{"name": otherName},
	}
	client.gui.events <- Click{name: "manual"}
	client.AdvanceTo(uiStateNewContact2)
}

func proceedToPairedWithNames(t *testing.T, client1, client2 *TestClient, name1, name2 string, server *TestServer) {
	proceedToKeyExchange(t, client1, server, name2)
	proceedToKeyExchange(t, client2, server, name1)

	client1.gui.events <- Click{
		name:      "process",
		textViews: map[string]string{"kxin": client2.gui.text["kxout"]},
	}
	client1.AdvanceTo(uiStateShowContact)

	client2.gui.events <- Click{
		name:      "process",
		textViews: map[string]string{"kxin": client1.gui.text["kxout"]},
	}
	client2.AdvanceTo(uiStateShowContact)
}

func proceedToPaired(t *testing.T, client1, client2 *TestClient, server *TestServer) {
	proceedToPairedWithNames(t, client1, client2, "client1", "client2", server)
}

const (
	simulateOldRatchet = iota
	simulateNewRatchet
	simulateNewRatchetV2
)

func TestKeyExchange(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	testKeyExchange(t, simulateNewRatchetV2, simulateNewRatchetV2)
}

func TestKeyExchangeCrossVersion(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	testKeyExchange(t, simulateNewRatchetV2, simulateNewRatchet)
	testKeyExchange(t, simulateNewRatchetV2, simulateOldRatchet)
	testKeyExchange(t, simulateNewRatchet, simulateNewRatchet)
	testKeyExchange(t, simulateNewRatchet, simulateOldRatchet)
	testKeyExchange(t, simulateOldRatchet, simulateOldRatchet)
}

func testKeyExchange(t *testing.T, versionA, versionB int) {
	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	switch versionA {
	case simulateOldRatchet:
		client1.simulateOldClient = true
	case simulateNewRatchet:
		client1.disableV2Ratchet = true
	case simulateNewRatchetV2:
		client1.disableV2Ratchet = false
	}

	client2, err := NewTestClient(t, "client2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	switch versionB {
	case simulateOldRatchet:
		client2.simulateOldClient = true
	case simulateNewRatchet:
		client2.disableV2Ratchet = true
	case simulateNewRatchetV2:
		client1.disableV2Ratchet = false
	}

	proceedToKeyExchange(t, client1, server, "client2")
	proceedToKeyExchange(t, client2, server, "client1")

	client1.Reload()
	client1.AdvanceTo(uiStateMain)
	client1.gui.events <- Click{
		name: client1.contactsUI.entries[0].boxName,
	}
	client1.AdvanceTo(uiStateNewContact2)
	client2.Reload()
	client2.AdvanceTo(uiStateMain)
	client2.gui.events <- Click{
		name: client2.contactsUI.entries[0].boxName,
	}
	client2.AdvanceTo(uiStateNewContact2)

	client1.gui.events <- Click{
		name:      "process",
		textViews: map[string]string{"kxin": "rubbish"},
	}
	t.Log("Waiting for error from garbage key exchange")
	for {
		if err := client1.gui.WaitForSignal(); err != nil {
			break
		}
	}

	kxBytes := []byte(client2.gui.text["kxout"])
	kxBytes[55] ^= 1
	client1.gui.events <- Click{
		name:      "process",
		textViews: map[string]string{"kxin": string(kxBytes)},
	}
	t.Log("Waiting for error from corrupt key exchange")
	for {
		if err := client1.gui.WaitForSignal(); err != nil {
			break
		}
	}
	client1.gui.events <- Click{
		name:      "process",
		textViews: map[string]string{"kxin": client2.gui.text["kxout"]},
	}
	client1.AdvanceTo(uiStateShowContact)

	client2.gui.events <- Click{
		name:      "process",
		textViews: map[string]string{"kxin": client1.gui.text["kxout"]},
	}
	client2.AdvanceTo(uiStateShowContact)
}

func contactByName(client *TestClient, name string) (id uint64, contact *Contact) {
	for id, contact = range client.contacts {
		if contact.name == name {
			return
		}
	}
	panic("contact not found: " + name)
}

func clickOnContact(client *TestClient, name string) {
	for id, contact := range client.contacts {
		if contact.name == name {
			for _, entry := range client.contactsUI.entries {
				if entry.id == id {
					client.gui.events <- Click{name: entry.boxName}
					return
				}
			}
		}
	}
	panic("contact not found: " + name)
}

func selectContact(t *testing.T, client *TestClient, name string) {
	id, _ := contactByName(client, name)
	var boxName string
	for _, item := range client.contactsUI.entries {
		if item.id == id {
			boxName = item.boxName
		}
	}
	if len(boxName) == 0 {
		panic("couldn't find box for given name")
	}
	client.gui.events <- Click{name: boxName}
	client.AdvanceTo(uiStateShowContact)
}

func sendMessage(client *TestClient, to string, message string) {
	composeMessage(client, to, message)
	transmitMessage(client, false)
}

func composeMessage(client *TestClient, to string, message string) {
	client.gui.events <- Click{name: "compose"}
	client.AdvanceTo(uiStateCompose)

	client.gui.events <- Click{
		name:      "send",
		combos:    map[string]string{"to": to},
		textViews: map[string]string{"body": message},
	}

	client.AdvanceTo(uiStateOutbox)
}

func transmitMessage(client *TestClient, readActions bool) {
	ackChan := make(chan bool)
	client.fetchNowChan <- ackChan

WaitForAck:
	for {
		select {
		case ack := <-client.gui.signal:
			if readActions {
			ReadActions:
				for {
					select {
					case <-client.gui.actions:
					default:
						break ReadActions
					}
				}
			}
			ack <- true
		case <-ackChan:
			break WaitForAck
		}
	}
}

func fetchMessage(client *TestClient) (from string, msg *InboxMessage) {
	ackChan := make(chan bool)
	initialInboxLen := len(client.inbox)
	client.fetchNowChan <- ackChan

WaitForAck:
	for {
		select {
		case ack := <-client.gui.signal:
			ack <- true
		case <-ackChan:
			break WaitForAck
		}
	}

	if len(client.inbox) <= initialInboxLen {
		return "", nil
	}
	msg = client.inbox[len(client.inbox)-1]
	if msg.from != 0 {
		from = client.contacts[msg.from].name
	}
	return
}

func TestMessageExchange(t *testing.T) {
	testMessageExchange(t, false)
}

func TestMessageExchangeCrossVersion(t *testing.T) {
	testMessageExchange(t, true)
}

func testMessageExchange(t *testing.T, crossVersion bool) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()
	client1.simulateOldClient = crossVersion

	client2, err := NewTestClient(t, "client2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	proceedToPaired(t, client1, client2, server)

	var initialCurrentDH [32]byte
	if crossVersion {
		for _, contact := range client1.contacts {
			if contact.name == "client2" {
				copy(initialCurrentDH[:], contact.currentDHPrivate[:])
			}
		}
	}

	for i := 0; i < 3; i++ {
		testMsg := fmt.Sprintf("test message %d", i)
		sendMessage(client1, "client2", testMsg)
		from, msg := fetchMessage(client2)
		if from != "client1" {
			t.Fatalf("message from %s, expected client1", from)
		}
		if string(msg.message.Body) != testMsg {
			t.Fatalf("Incorrect message contents: %#v", msg)
		}

		sendMessage(client2, "client1", testMsg)
		from, msg = fetchMessage(client1)
		if from != "client2" {
			t.Fatalf("message from %s, expected client2", from)
		}
		if string(msg.message.Body) != testMsg {
			t.Fatalf("Incorrect message contents: %#v", msg)
		}
	}

	if crossVersion {
		// Ensure that the DH secrets are advancing.
		for _, contact := range client1.contacts {
			if contact.name == "client2" {
				if bytes.Equal(initialCurrentDH[:], contact.currentDHPrivate[:]) {
					t.Fatalf("DH secrets aren't advancing!")
				}
			}
		}
	}
}

func TestACKs(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	client2, err := NewTestClient(t, "client2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	proceedToPaired(t, client1, client2, server)

	const testMsg = "test message"
	sendMessage(client1, "client2", testMsg)
	from, msg := fetchMessage(client2)
	if from != "client1" {
		t.Fatalf("message from %s, expected client1", from)
	}
	if string(msg.message.Body) != testMsg {
		t.Fatalf("Incorrect message contents: %#v", msg)
	}
	if !client1.outbox[0].acked.IsZero() {
		t.Fatalf("client1 incorrectly believes that its message has been acked")
	}
	client2.gui.events <- Click{
		name: client2.inboxUI.entries[0].boxName,
	}
	client2.AdvanceTo(uiStateInbox)
	client2.gui.events <- Click{
		name: "ack",
	}
	client2.AdvanceTo(uiStateInbox)

	ackChan := make(chan bool)
	client2.fetchNowChan <- ackChan
WaitForAck:
	for {
		select {
		case ack := <-client2.gui.signal:
			ack <- true
		case <-ackChan:
			break WaitForAck
		}
	}

	fetchMessage(client1)

	if client1.outbox[0].acked.IsZero() {
		t.Fatalf("client1 doesn't believe that its message has been acked")
	}

	client1.gui.events <- Click{
		name: client1.outboxUI.entries[0].boxName,
	}
	client1.AdvanceTo(uiStateOutbox)
	client1.gui.events <- Click{
		name: "delete",
	}
	client1.AdvanceTo(uiStateMain)

	if l := len(client1.outboxUI.entries); l > 0 {
		t.Fatalf("client1 still has %d outbox UI entries after delete", l)
	}

	if l := len(client1.outbox); l > 0 {
		t.Fatalf("client1 still has %d outbox entries after delete", l)
	}
}

func TestHalfPairedMessageExchange(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	client2, err := NewTestClient(t, "client2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	proceedToKeyExchange(t, client1, server, "client2")
	proceedToKeyExchange(t, client2, server, "client1")

	client1KX := client1.gui.text["kxout"]
	client1.gui.events <- Click{
		name:      "process",
		textViews: map[string]string{"kxin": client2.gui.text["kxout"]},
	}
	client1.AdvanceTo(uiStateShowContact)

	// Now client1 is paired with client2, but client2 is still pending on
	// client1.

	// Send a message from client1 to client2.
	const testMsg = "test message"
	sendMessage(client1, "client2", testMsg)
	from, msg := fetchMessage(client2)
	if from != "client1" {
		t.Fatalf("message from %s, expected client1", from)
	}
	if len(msg.sealed) == 0 {
		t.Fatalf("no sealed message from client2")
	}
	if len(client2.inboxUI.entries) == 0 {
		t.Fatalf("no pending UI entry in client2")
	}

	// Check that viewing the message in client2 doesn't crash anything.
	client2.gui.events <- Click{
		name: client2.inboxUI.entries[0].boxName,
	}
	client2.AdvanceTo(uiStateInbox)

	client2.Reload()
	client2.AdvanceTo(uiStateMain)

	// Select the pending contact in client2 to complete the key exchange.
	client2.gui.events <- Click{
		name: client2.contactsUI.entries[0].boxName,
	}
	client2.AdvanceTo(uiStateNewContact)
	client2.gui.events <- Click{
		name:      "process",
		textViews: map[string]string{"kxin": client1KX},
	}
	client2.AdvanceTo(uiStateShowContact)
	client2.gui.events <- Click{
		name: client2.inboxUI.entries[0].boxName,
	}
	client2.AdvanceTo(uiStateInbox)

	if s := client2.gui.text["body"]; s != testMsg {
		t.Fatalf("resolved message is incorrect: %s", s)
	}
}

func TestDraft(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := NewTestClient(t, "client", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	proceedToMainUI(t, client, server)
	client.gui.events <- Click{name: "compose"}
	client.AdvanceTo(uiStateCompose)

	if l := len(client.drafts); l != 1 {
		t.Fatalf("Bad number of drafts: %d", l)
	}
	var draftID uint64
	for id := range client.drafts {
		draftID = id
		break
	}

	const initialText = "wibble wobble"

	client.gui.events <- Update{
		name: "body",
		text: initialText,
	}
	client.Reload()
	client.AdvanceTo(uiStateMain)

	if l := len(client.drafts); l != 1 {
		t.Fatalf("Bad number of drafts after reload: %d", l)
	}

	if l := len(client.draftsUI.entries); l != 1 {
		t.Fatalf("Bad number of draft UI entries after reload: %d", l)
	}

	if id := client.draftsUI.entries[0].id; id != draftID {
		t.Fatalf("Incorrect draft ID after reload: %d vs %d", id, draftID)
	}

	client.gui.events <- Click{name: client.draftsUI.entries[0].boxName}
	client.AdvanceTo(uiStateCompose)
	if text := client.gui.text["body"]; text != initialText {
		t.Fatalf("Wrong message text after reload: '%s' vs '%s'", text, initialText)
	}

	attachmentFile := filepath.Join(client.stateDir, "attachment")
	if err := ioutil.WriteFile(attachmentFile, []byte(initialText), 0644); err != nil {
		t.Fatalf("Failed to write attachment file: %s", err)
	}

	client.gui.events <- Click{name: "attach"}
	client.gui.events <- OpenResult{path: attachmentFile, ok: true}

	client.Reload()
	client.AdvanceTo(uiStateMain)
	client.gui.events <- Click{name: client.draftsUI.entries[0].boxName}
	client.AdvanceTo(uiStateCompose)

	const labelPrefix = "attachment-label-"
	var attachmentID uint64
	for name := range client.gui.text {
		if strings.HasPrefix(name, labelPrefix) {
			attachmentID, err = strconv.ParseUint(name[len(labelPrefix):], 16, 64)
			if err != nil {
				t.Fatalf("Failed to parse attachment label: %s", name)
			}
			break
		}
	}

	if attachmentID == 0 {
		t.Fatalf("failed to find attachment after reload")
	}

	client.gui.events <- Click{name: fmt.Sprintf("remove-%x", attachmentID)}
	client.Reload()
	client.AdvanceTo(uiStateMain)
	client.gui.events <- Click{name: client.draftsUI.entries[0].boxName}
	client.AdvanceTo(uiStateCompose)

	for name := range client.gui.text {
		if strings.HasPrefix(name, labelPrefix) {
			t.Fatalf("Found attachment after removing")
		}
	}

	errorFile := filepath.Join(client.stateDir, "error")
	if err := ioutil.WriteFile(errorFile, nil, 0); err != nil {
		t.Fatalf("Failed to write error file: %s", err)
	}

	client.gui.events <- Click{name: "attach"}
	client.gui.WaitForFileOpen()
	client.gui.events <- OpenResult{path: attachmentFile, ok: true}
	client.gui.events <- Click{name: "attach"}
	client.gui.WaitForFileOpen()
	client.gui.events <- OpenResult{path: errorFile, ok: true}
	client.gui.WaitForSignal()

	attachmentID = 0
	const errorPrefix = "attachment-error-"
	for name := range client.gui.text {
		if strings.HasPrefix(name, errorPrefix) {
			attachmentID, err = strconv.ParseUint(name[len(errorPrefix):], 16, 64)
			if err != nil {
				t.Fatalf("Failed to parse attachment label: %s", name)
			}
			break
		}
	}

	if attachmentID == 0 {
		t.Fatalf("failed to find error attachment")
	}

	client.gui.events <- Click{name: fmt.Sprintf("remove-%x", attachmentID)}
	client.gui.WaitForSignal()
}

func TestDraftDiscard(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := NewTestClient(t, "client", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	proceedToMainUI(t, client, server)
	client.gui.events <- Click{name: "compose"}
	client.AdvanceTo(uiStateCompose)

	if l := len(client.drafts); l != 1 {
		t.Fatalf("Bad number of drafts: %d", l)
	}

	client.gui.events <- Click{name: "discard"}
	client.AdvanceTo(uiStateMain)

	if l := len(client.drafts); l != 0 {
		t.Fatalf("Bad number of drafts after discard: %d", l)
	}
}

func testDetached(t *testing.T, upload bool) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	client2, err := NewTestClient(t, "client2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	proceedToPaired(t, client1, client2, server)
	client1.gui.events <- Click{name: "compose"}
	client1.AdvanceTo(uiStateCompose)

	plaintextPath := filepath.Join(client1.stateDir, "file")
	ciphertextPath := filepath.Join(client1.stateDir, "encrypted")
	plaintext := make([]byte, 200*1024)
	io.ReadFull(rand.Reader, plaintext)
	if err := ioutil.WriteFile(plaintextPath, plaintext, 0644); err != nil {
		t.Fatal(err)
	}

	client1.gui.events <- Click{name: "attach"}
	client1.gui.WaitForFileOpen()
	client1.gui.events <- OpenResult{path: plaintextPath, ok: true}
	client1.gui.WaitForSignal()
	for name := range client1.gui.text {
		const labelPrefix = "attachment-label-"
		if strings.HasPrefix(name, labelPrefix) {
			attachmentID, err := strconv.ParseUint(name[len(labelPrefix):], 16, 64)
			if err != nil {
				t.Fatalf("Failed to parse attachment label: %s", name)
			}
			if upload {
				client1.gui.events <- Click{name: fmt.Sprintf("attachment-upload-%x", attachmentID)}
			} else {
				client1.gui.events <- Click{name: fmt.Sprintf("attachment-convert-%x", attachmentID)}
			}
			break
		}
	}
	if !upload {
		fo := client1.gui.WaitForFileOpen()
		client1.gui.events <- OpenResult{path: ciphertextPath, ok: true, arg: fo.arg}
		client1.gui.WaitForSignal()
	}

	var draft *Draft
	for _, d := range client1.drafts {
		draft = d
		break
	}

	for len(draft.detachments) == 0 {
		client1.gui.WaitForSignal()
	}

	client1.gui.events <- Click{
		name:      "send",
		combos:    map[string]string{"to": "client2"},
		textViews: map[string]string{"body": "foo"},
	}

	client1.AdvanceTo(uiStateOutbox)
	ackChan := make(chan bool)
	client1.fetchNowChan <- ackChan

WaitForAck:
	for {
		select {
		case ack := <-client1.gui.signal:
			ack <- true
		case <-ackChan:
			break WaitForAck
		}
	}

	_, msg := fetchMessage(client2)
	if len(msg.message.DetachedFiles) != 1 {
		t.Fatalf("message received with no detachments")
	}

	for _, e := range client2.inboxUI.entries {
		if e.id == msg.id {
			client2.gui.events <- Click{name: e.boxName}
			break
		}
	}

	client2.AdvanceTo(uiStateInbox)
	if upload {
		client2.gui.events <- Click{name: "detachment-download-0"}
	} else {
		client2.gui.events <- Click{name: "detachment-decrypt-0"}
	}
	fo := client2.gui.WaitForFileOpen()
	outputPath := filepath.Join(client1.stateDir, "output")
	if upload {
		client2.gui.events <- OpenResult{ok: true, path: outputPath, arg: fo.arg}
	} else {
		client2.gui.events <- OpenResult{ok: true, path: ciphertextPath, arg: fo.arg}
		fo = client2.gui.WaitForFileOpen()
		client2.gui.events <- OpenResult{ok: true, path: outputPath, arg: fo.arg}
	}
	client2.gui.WaitForSignal()

	var id uint64
	for dID := range msg.decryptions {
		id = dID
		break
	}

	if id == 0 {
		t.Fatalf("Failed to get id of decryption")
	}

	for len(msg.decryptions) > 0 {
		client2.gui.WaitForSignal()
	}

	result, err := ioutil.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(result, plaintext) {
		t.Fatalf("bad decryption")
	}
}

func TestDetachedFile(t *testing.T) {
	testDetached(t, false)
}

func TestUploadDownload(t *testing.T) {
	testDetached(t, true)
}

func TestLogOverflow(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()
	proceedToMainUI(t, client1, server)

	client1.gui.events <- Click{name: client1.clientUI.entries[1].boxName}
	client1.AdvanceTo(uiStateLog)

	for i := 0; i < 2*(logLimit+logSlack); i++ {
		client1.log.Printf("%d", i)
	}
}

func TestServerAnnounce(t *testing.T) {
	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := NewTestClient(t, "client", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	proceedToMainUI(t, client, server)

	const testMessage = "Hello world"
	announce := &pond.Message{
		Id:           proto.Uint64(0),
		Time:         proto.Int64(time.Now().Unix()),
		Body:         []byte(testMessage),
		MyNextDh:     []byte{},
		BodyEncoding: pond.Message_RAW.Enum(),
	}
	announceBytes, err := proto.Marshal(announce)
	if err != nil {
		t.Fatalf("Failed to marshal announce message: %s", err)
	}
	if err := ioutil.WriteFile(fmt.Sprintf("%s/accounts/%x/announce-00000000", server.stateDir, client.identityPublic[:]), announceBytes, 0666); err != nil {
		t.Fatalf("Failed to write announce message: %s", err)
	}

	fetchMessage(client)

	if len(client.inbox) != 1 {
		t.Fatalf("Inbox doesn't have a message")
	}
	client.gui.events <- Click{
		name: client.inboxUI.entries[0].boxName,
	}
	client.AdvanceTo(uiStateInbox)
	if s := client.gui.text["body"]; s != testMessage {
		t.Fatalf("resolved message is incorrect: %s", s)
	}

	client.Reload()
	client.AdvanceTo(uiStateMain)
}

func TestRevoke(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	client2, err := NewTestClient(t, "client2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	client3, err := NewTestClient(t, "client3", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client3.Close()

	client4, err := NewTestClient(t, "client4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client4.Close()

	proceedToPaired(t, client1, client2, server)
	proceedToPairedWithNames(t, client1, client3, "client1", "client3", server)
	proceedToPairedWithNames(t, client1, client4, "client1", "client4", server)

	initialGeneration := client1.generation

	// Have client4 send a message before the revocation.
	const beforeRevocationMsg = "from before revocation"
	sendMessage(client4, "client1", beforeRevocationMsg)

	var client1FromClient2 *Contact
	for _, candidate := range client2.contacts {
		if candidate.name == "client1" {
			client1FromClient2 = candidate
			break
		}
	}
	if client1FromClient2.generation != initialGeneration {
		t.Errorf("Initial generations don't match")
	}

	var client1FromClient3 *Contact
	for _, candidate := range client3.contacts {
		if candidate.name == "client1" {
			client1FromClient3 = candidate
			break
		}
	}

	client1.gui.events <- Click{name: client1.contactsUI.entries[0].boxName}
	client1.AdvanceTo(uiStateShowContact)
	client1.gui.events <- Click{name: "delete"}
	client1.gui.WaitForSignal() // button changes to "Confirm"
	client1.gui.events <- Click{name: "delete"}
	client1.AdvanceTo(uiStateRevocationComplete)

	if client1.generation != initialGeneration+1 {
		t.Errorf("Generation did not advance")
	}

	if len(client1.outboxUI.entries) != 1 {
		t.Errorf("No revocation entry found after click")
	}
	client1.Reload()
	client1.AdvanceTo(uiStateMain)

	if len(client1.outboxUI.entries) != 1 {
		t.Errorf("No revocation entry found after reload")
	}

	transmitMessage(client1, true)

	composeMessage(client2, "client1", "test1")
	// Select the contact before sending because we have previously crashed
	// in this case. See https://github.com/agl/pond/issues/96.
	client2.gui.events <- Click{name: client2.contactsUI.entries[0].boxName}
	client2.AdvanceTo(uiStateShowContact)
	transmitMessage(client2, false)
	client2.AdvanceTo(uiStateRevocationProcessed)

	if gen := client1FromClient2.generation; gen != client1.generation {
		t.Errorf("Generation number didn't update: found %d, want %d", gen, client1.generation)
	}
	if !client1FromClient2.revokedUs {
		t.Errorf("Client1 isn't marked as revoked")
	}

	sendMessage(client3, "client1", "test2")
	client3.AdvanceTo(uiStateRevocationProcessed)

	if gen := client1FromClient3.generation; gen != client1.generation {
		t.Errorf("Generation number didn't update for non-revoked: found %d, want %d", gen, client1.generation)
	}
	if client1FromClient3.revokedUs {
		t.Errorf("Client3 believes that it was revoked")
	}

	// Have client3 resend.
	transmitMessage(client3, false)

	// Have client1 fetch the resigned message from client3, and the
	// message from client4 using previousTags.
	var seenClient3, seenClient4 bool
	for i := 0; i < 2; i++ {
		from, msg := fetchMessage(client1)
		switch from {
		case "client3":
			if seenClient3 {
				t.Fatalf("client3 message observed twice")
			}
			if string(msg.message.Body) != "test2" {
				t.Fatalf("Incorrect message contents from client3: %#v", msg)
			}
			seenClient3 = true
		case "client4":
			if seenClient4 {
				t.Fatalf("client4 message observed twice")
			}
			if string(msg.message.Body) != beforeRevocationMsg {
				t.Fatalf("Incorrect message contents client4: %#v", msg)
			}
			seenClient4 = true
		}
	}
}

func TestMultiRevoke(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	client2, err := NewTestClient(t, "client2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	client3, err := NewTestClient(t, "client3", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client3.Close()

	client4, err := NewTestClient(t, "client4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client4.Close()

	proceedToPaired(t, client1, client2, server)
	proceedToPairedWithNames(t, client1, client3, "client1", "client3", server)
	proceedToPairedWithNames(t, client1, client4, "client1", "client4", server)

	revokeContact := func(client *TestClient, name string) {
		found := false
		for _, ent := range client.contactsUI.entries {
			if client.contacts[ent.id].name == name {
				client.gui.events <- Click{name: ent.boxName}
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Couldn't find contact %s", name)
		}
		client.AdvanceTo(uiStateShowContact)
		client.gui.events <- Click{name: "delete"}
		client.gui.WaitForSignal() // button changes to "Confirm"
		client.gui.events <- Click{name: "delete"}
		client.AdvanceTo(uiStateRevocationComplete)

		transmitMessage(client, true)
	}

	// Revoke client3 and 4 from client1.
	revokeContact(client1, "client3")
	revokeContact(client1, "client4")

	// Send a message from client2 to client1. It should hit two
	// revocations, which should be returned in a single error from the
	// server.
	sendMessage(client2, "client1", "test")
	client2.AdvanceTo(uiStateRevocationProcessed)
	client2.AdvanceTo(uiStateRevocationProcessed)

	if g := client2.contacts[client2.contactsUI.entries[0].id].generation; g != client1.generation {
		t.Errorf("Generations don't match: %d vs %d", g, client1.generation)
	}
}

func startPANDAKeyExchange(t *testing.T, client *TestClient, server *TestServer, otherName, sharedSecret string) {
	proceedToMainUI(t, client, server)

	client.gui.events <- Click{name: "newcontact"}
	client.AdvanceTo(uiStateNewContact)

	client.gui.events <- Click{
		name:    "name",
		entries: map[string]string{"name": otherName},
	}
	client.gui.events <- Click{name: "shared"}
	client.AdvanceTo(uiStateNewContact2)

	client.gui.events <- Click{
		name:    "begin",
		entries: map[string]string{"shared": sharedSecret},
	}
}

func TestPANDA(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	client2, err := NewTestClient(t, "client2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	mp := panda.NewSimpleMeetingPlace()
	newMeetingPlace := func() panda.MeetingPlace {
		return mp
	}
	client1.newMeetingPlace = newMeetingPlace
	client2.newMeetingPlace = newMeetingPlace

	startPANDAKeyExchange(t, client1, server, "client2", "shared secret")

	client1.ReloadWithMeetingPlace(mp)

	startPANDAKeyExchange(t, client2, server, "client1", "shared secret")

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		client1.AdvanceTo(uiStatePANDAComplete)
		wg.Done()
	}()
	go func() {
		client2.AdvanceTo(uiStatePANDAComplete)
		wg.Done()
	}()
	wg.Wait()

	var client2FromClient1 *Contact
	for _, contact := range client1.contacts {
		client2FromClient1 = contact
		break
	}

	var client1FromClient2 *Contact
	for _, contact := range client2.contacts {
		client1FromClient2 = contact
		break
	}

	if g := client2FromClient1.generation; g != client2.generation {
		t.Errorf("Generation mismatch %d vs %d", g, client1.generation)
	}

	if g := client1FromClient2.generation; g != client1.generation {
		t.Errorf("Generation mismatch %d vs %d", g, client1.generation)
	}
}

func TestReadingOldStateFiles(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", &TestClientOptions{
		initialStateFile: "testdata/state-old",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	client1.AdvanceTo(uiStateMain)
	client1.Reload()
	client1.AdvanceTo(uiStateMain)
}

func testReplyACKs(t *testing.T, reloadDraft bool, abortSend bool) {
	// Test that a message is acked by sending a reply. If reloadDraft is
	// true then the message is reloaded as draft before sending.
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	client2, err := NewTestClient(t, "client2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	proceedToPaired(t, client1, client2, server)

	const testMsg = "test message"
	sendMessage(client1, "client2", testMsg)
	from, _ := fetchMessage(client2)
	if from != "client1" {
		t.Fatalf("message from %s, expected client1", from)
	}
	if !client1.outbox[0].acked.IsZero() {
		t.Fatalf("client1 incorrectly believes that its message has been acked")
	}
	client2.gui.events <- Click{
		name: client2.inboxUI.entries[0].boxName,
	}
	client2.AdvanceTo(uiStateInbox)
	client2.gui.events <- Click{
		name: "reply",
	}
	client2.AdvanceTo(uiStateCompose)

	if reloadDraft {
		client2.gui.events <- Click{
			name: client2.draftsUI.entries[0].boxName,
		}
		client2.AdvanceTo(uiStateCompose)
	}

	client2.gui.events <- Click{
		name:      "send",
		combos:    map[string]string{"to": "client1"},
		textViews: map[string]string{"body": "reply message"},
	}
	client2.AdvanceTo(uiStateOutbox)

	if abortSend {
		client2.gui.events <- Click{name: "abort"}
		client2.AdvanceTo(uiStateCompose)

		client2.gui.events <- Click{
			name:      "send",
			combos:    map[string]string{"to": "client1"},
			textViews: map[string]string{"body": "reply message"},
		}
		client2.AdvanceTo(uiStateOutbox)
	}

	ackChan := make(chan bool)
	client2.fetchNowChan <- ackChan

WaitForAck:
	for {
		select {
		case ack := <-client2.gui.signal:
			ack <- true
		case <-ackChan:
			break WaitForAck
		}
	}

	from, _ = fetchMessage(client1)
	if from != "client2" {
		t.Fatalf("ack received from wrong contact: %s", from)
	}

	if client1.outbox[0].acked.IsZero() {
		t.Fatalf("client1 doesn't believe that its message has been acked")
	}
	if !client2.inbox[0].acked {
		t.Fatalf("client2 doesn't believe that it has acked the message")
	}
}

func TestReplyACKs(t *testing.T) {
	testReplyACKs(t, false, false)
}

func TestReplyACKsWithDraft(t *testing.T) {
	testReplyACKs(t, true, false)
}

func TestReplyACKsWithDraftAndAbort(t *testing.T) {
	testReplyACKs(t, true, true)
}

func TestCliId(t *testing.T) {
	id := cliId(0x7ab8)
	s := id.String()
	t.Log(s)
	if result, ok := cliIdFromString(s); !ok || result != id {
		t.Fatalf("CliId parse failed: got %d, want %d", result, id)
	}
}

func TestSendToPendingContact(t *testing.T) {
	// Test that it's not possible to send a message to a pending contact.
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client, err := NewTestClient(t, "client", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	proceedToMainUI(t, client, server)

	client.gui.events <- Click{name: "newcontact"}
	client.AdvanceTo(uiStateNewContact)

	client.gui.events <- Click{
		name:    "name",
		entries: map[string]string{"name": "pendingContact"},
	}
	client.gui.events <- Click{name: "manual"}
	client.AdvanceTo(uiStateNewContact2)

	client.gui.events <- Click{name: "compose"}
	client.AdvanceTo(uiStateCompose)

	if contacts, ok := client.gui.combos["to"]; !ok || len(contacts) > 0 {
		t.Error("can send message to pending contact")
	}
}

func TestDelete(t *testing.T) {
	// Test that deleting contacts works.
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	client2, err := NewTestClient(t, "client2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	// Setup a normal pair of clients.
	proceedToPaired(t, client1, client2, server)

	const testMsg = "test message"
	sendMessage(client1, "client2", testMsg)
	from, _ := fetchMessage(client2)
	if from != "client1" {
		t.Fatalf("message from %s, expected client1", from)
	}

	// Start an incomplete, manual exchange.
	proceedToKeyExchange(t, client1, server, "client3")

	// Start a PANDA exchange.
	mp := panda.NewSimpleMeetingPlace()
	newMeetingPlace := func() panda.MeetingPlace {
		return mp
	}
	client1.newMeetingPlace = newMeetingPlace
	startPANDAKeyExchange(t, client1, server, "client4", "secret")
	client1.AdvanceTo(uiStateShowContact)

	clickOnContact(client1, "client2")
	client1.gui.events <- Click{name: "delete"}
	client1.gui.events <- Click{name: "delete"}
	client1.AdvanceTo(uiStateRevocationComplete)

	if len(client1.inbox) > 0 {
		t.Errorf("still entries in inbox")
	}

	for _, msg := range client1.outbox {
		if !msg.revocation {
			t.Errorf("still entries in outbox")
			break
		}
	}

	clickOnContact(client1, "client3")
	client1.gui.events <- Click{name: "abort"}
	client1.AdvanceTo(uiStateRevocationComplete)

	clickOnContact(client1, "client4")
	client1.gui.events <- Click{name: "delete"}
	client1.gui.events <- Click{name: "delete"}
	client1.AdvanceTo(uiStateRevocationComplete)

	if len(client1.contacts) > 0 {
		t.Errorf("still contacts")
	}

	client1.Reload()
	client1.AdvanceTo(uiStateMain)
}

func TestExpireMessage(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	client2, err := NewTestClient(t, "client2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	// Setup a normal pair of clients.
	proceedToPaired(t, client1, client2, server)

	const testMsg = "test message"
	sendMessage(client1, "client2", testMsg)
	from, _ := fetchMessage(client2)
	if from != "client1" {
		t.Fatalf("message from %s, expected client1", from)
	}

	if n := len(client2.inbox); n != 1 {
		t.Fatalf("Bad initial number of inbox messages: %d", n)
	}

	baseTime := time.Now()
	client2.testTimerChan <- baseTime
	client2.AdvanceTo(uiStateTimerComplete)

	if n := len(client2.inbox); n != 1 {
		t.Fatalf("Bad number of messages after first timer: %d", n)
	}

	if n := len(client2.inboxUI.entries); n != 1 {
		t.Fatalf("Bad number of messages in listUI after first timer: %d", n)
	}

	if client2.inboxUI.entries[0].background != colorGray {
		t.Fatalf("Bad message background after first timer")
	}

	// Advance the clock so that the message should be indicated as near
	// deletion.

	client2.nowFunc = func() time.Time {
		return baseTime.Add(messagePreIndicationLifetime + 10*time.Second)
	}

	client2.testTimerChan <- baseTime
	client2.AdvanceTo(uiStateTimerComplete)

	if n := len(client2.inboxUI.entries); n != 1 {
		t.Fatalf("Bad number of messages in listUI: %d", n)
	}

	if client2.inboxUI.entries[0].background != colorDeleteSoon {
		t.Fatalf("Bad message background after second timer")
	}

	client2.Reload()
	client2.AdvanceTo(uiStateMain)

	if n := len(client2.inboxUI.entries); n != 1 {
		t.Fatalf("Bad number of messages in listUI after reload: %d", n)
	}

	if client2.inboxUI.entries[0].background != colorDeleteSoon {
		t.Fatalf("Bad message background after second reload")
	}

	client2.nowFunc = func() time.Time {
		return baseTime.Add(messageLifetime + 10*time.Second)
	}

	client2.Reload()
	client2.AdvanceTo(uiStateMain)

	if n := len(client2.inboxUI.entries); n != 1 {
		t.Fatalf("Bad number of messages in listUI after second reload: %d", n)
	}

	if client2.inboxUI.entries[0].background != colorImminently {
		t.Fatalf("Bad message background after second reload")
	}

	client2.testTimerChan <- baseTime
	client2.AdvanceTo(uiStateTimerComplete)

	if n := len(client2.inboxUI.entries); n != 1 {
		t.Fatalf("Bad number of messages in listUI after grace period timer: %d", n)
	}

	if client2.inboxUI.entries[0].background != colorImminently {
		t.Fatalf("Bad message background after grace period timer")
	}

	client2.nowFunc = func() time.Time {
		return baseTime.Add(messageLifetime + 10*time.Second + messageGraceTime)
	}

	client2.testTimerChan <- baseTime
	client2.AdvanceTo(uiStateTimerComplete)

	if n := len(client2.inboxUI.entries); n != 1 {
		t.Fatalf("Bad number of messages in listUI after expiry: %d", n)
	}

	if n := len(client2.inbox); n != 1 {
		t.Fatalf("Bad number of messages in inbox after expiry: %d", n)
	}
}

func TestRetainMessage(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	client2, err := NewTestClient(t, "client2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	// Setup a normal pair of clients.
	proceedToPaired(t, client1, client2, server)

	const testMsg = "test message"
	sendMessage(client1, "client2", testMsg)
	from, _ := fetchMessage(client2)
	if from != "client1" {
		t.Fatalf("message from %s, expected client1", from)
	}

	if n := len(client2.inbox); n != 1 {
		t.Fatalf("Bad initial number of inbox messages: %d", n)
	}

	if n := len(client2.inboxUI.entries); n != 1 {
		t.Fatalf("Bad initial number of messages in listUI: %d", n)
	}

	msg := client2.inbox[0]
	if msg.retained {
		t.Fatalf("Retained flag is initially set")
	}

	client2.gui.events <- Click{
		name: client2.inboxUI.entries[0].boxName,
	}
	client2.AdvanceTo(uiStateInbox)
	client2.gui.events <- Click{
		name:   "retain",
		checks: map[string]bool{"retain": true},
	}
	client2.AdvanceTo(uiStateInbox)

	if !msg.retained {
		t.Fatalf("Retained flag not set")
	}

	client2.Reload()
	client2.AdvanceTo(uiStateMain)

	msg = client2.inbox[0]
	if !msg.retained {
		t.Fatalf("Retained flag lost")
	}

	baseTime := time.Now()
	client2.nowFunc = func() time.Time {
		return baseTime.Add(messageLifetime + 10*time.Second)
	}

	client2.testTimerChan <- baseTime
	client2.AdvanceTo(uiStateTimerComplete)

	if n := len(client2.inbox); n != 1 {
		t.Fatalf("Message was deleted while retain flag set")
	}

	client2.gui.events <- Click{
		name: client2.inboxUI.entries[0].boxName,
	}
	client2.AdvanceTo(uiStateInbox)
	client2.gui.events <- Click{
		name:   "retain",
		checks: map[string]bool{"retain": false},
	}
	client2.AdvanceTo(uiStateInbox)

	if msg.retained {
		t.Fatalf("Retain flag not cleared")
	}

	client2.testTimerChan <- baseTime
	client2.AdvanceTo(uiStateTimerComplete)

	if n := len(client2.inbox); n != 1 {
		t.Fatalf("Message was deleted while in grace period")
	}

	client2.nowFunc = func() time.Time {
		return baseTime.Add(messageLifetime + messageGraceTime + 20*time.Second)
	}

	client2.testTimerChan <- baseTime
	client2.AdvanceTo(uiStateTimerComplete)

	if n := len(client2.inbox); n != 1 {
		t.Fatalf("Message deleted while selected")
	}

	client2.gui.events <- Click{
		name: "compose",
	}
	client2.AdvanceTo(uiStateCompose)

	client2.testTimerChan <- baseTime
	client2.AdvanceTo(uiStateTimerComplete)

	if n := len(client2.inbox); n != 0 {
		t.Fatalf("Message not deleted")
	}
}

func TestOutboxDeletion(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	client2, err := NewTestClient(t, "client2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	// Setup a normal pair of clients.
	proceedToPaired(t, client1, client2, server)

	const testMsg = "test message"
	sendMessage(client1, "client2", testMsg)

	client1.gui.events <- Click{
		name: "compose",
	}
	client1.AdvanceTo(uiStateCompose)

	if n := len(client1.outbox); n != 1 {
		t.Fatalf("Bad initial number of outbox messages: %d", n)
	}

	baseTime := time.Now()
	client1.nowFunc = func() time.Time {
		return baseTime.Add(messageLifetime + 10*time.Second)
	}

	client1.testTimerChan <- baseTime
	client1.AdvanceTo(uiStateTimerComplete)

	if n := len(client1.outbox); n != 0 {
		t.Fatalf("Outbox message not deleted")
	}
}

func TestStateFileLocking(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	client2, err := NewTestClient(t, "client2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	// Setup a normal pair of clients.
	proceedToPaired(t, client1, client2, server)

	stateFile, err := os.Open(filepath.Join(client1.stateDir, "state"))
	if err != nil {
		t.Fatalf("Failed to open state file")
	}
	defer stateFile.Close()
	if syscall.Flock(int(stateFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
		t.Fatalf("Was able to lock state file")
	}
}

func TestMergedACKs(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	client2, err := NewTestClient(t, "client2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	// Setup a normal pair of clients.
	proceedToPaired(t, client1, client2, server)

	// Send two messages to client2.
	sendMessage(client1, "client2", "foo1")
	fetchMessage(client2)
	sendMessage(client1, "client2", "foo2")
	fetchMessage(client2)

	// Ack the two messages in client2. The second ack should merge with
	// the first.
	client2.gui.events <- Click{
		name: client2.inboxUI.entries[0].boxName,
	}
	client2.AdvanceTo(uiStateInbox)
	client2.gui.events <- Click{
		name: "ack",
	}
	client2.AdvanceTo(uiStateInbox)

	client2.gui.events <- Click{
		name: client2.inboxUI.entries[1].boxName,
	}
	client2.AdvanceTo(uiStateInbox)
	client2.gui.events <- Click{
		name: "ack",
	}
	client2.AdvanceTo(uiStateInbox)

	// Send only one message from client2.
	transmitMessage(client2, false)

	// Both messages should be ACKed in client1 on receipt.
	fetchMessage(client1)

	for _, msg := range client1.outbox {
		if msg.acked.IsZero() {
			t.Errorf("Unacked message in client1's outbox.")
		}
	}
}

func TestEntombing(t *testing.T) {
	if parallel {
		t.Parallel()
	}

	server, err := NewTestServer(t)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	client1, err := NewTestClient(t, "client1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	client2, err := NewTestClient(t, "client2", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	// Setup a normal pair of clients.
	proceedToPaired(t, client1, client2, server)

	// Send a message so that we can be sure that the state file was
	// correctly recovered.
	sendMessage(client1, "client2", "foo1")
	fetchMessage(client2)

	// Emtomb client1.
	client1.gui.events <- Click{
		name: client1.clientUI.entries[0].boxName,
	}
	client1.AdvanceTo(uiStateShowIdentity)

	client1.gui.events <- OpenResult{ok: true, path: filepath.Join(client1.stateDir, "statefile.tomb")}
	client1.gui.events <- Click{name: "entomb"}
	client1.AdvanceTo(uiStateEntomb)
	client1.AdvanceTo(uiStateEntombComplete)

	keyHex := client1.gui.info
	client1.Reload()
	client1.AdvanceTo(uiStateLoading)
	client1.AdvanceTo(uiStateCreatePassphrase)
	client1.gui.events <- Click{
		name:    "next",
		entries: map[string]string{"pw": ""},
	}
	client1.AdvanceTo(uiStateErasureStorage)
	client1.gui.events <- Click{
		name: "continue",
	}

	client1.AdvanceTo(uiStateCreateAccount)
	client1.gui.events <- OpenResult{ok: true, path: filepath.Join(client1.stateDir, "statefile.tomb")}
	client1.gui.events <- Click{
		name:    "import",
		entries: map[string]string{"tombkey": keyHex},
	}
	client1.AdvanceTo(uiStateMain)

	if len(client1.outbox) != 1 {
		t.Fatalf("No messages in outbox")
	}
}
