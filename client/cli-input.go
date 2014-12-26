package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"code.google.com/p/go.crypto/ssh/terminal"
)

type cliCommand struct {
	name      string
	prototype interface{}
	desc      string
	context   inputContext
}

// inputContext is a flags type that indicates which contexts a given CLI
// command is valid in.
type inputContext int

const (
	contextInbox inputContext = 1 << iota
	contextOutbox
	contextDraft
	contextContact
)

var cliCommands = []cliCommand{
	{"abort", abortCommand{}, "Abort sending the current outbox message", contextOutbox},
	{"acknowledge", ackCommand{}, "Acknowledge the inbox message", contextInbox},
	{"attach", attachCommand{}, "Attach a file to the current draft", contextDraft},
	{"clear", clearCommand{}, "Clear terminal", 0},
	{"close", closeCommand{}, "Close currently opened object", contextDraft | contextInbox | contextOutbox | contextContact},
	{"compose", composeCommand{}, "Compose a new message", contextContact},
	{"contacts", showContactsCommand{}, "Show all known contacts", 0},
	{"delete", deleteCommand{}, "Delete a message or contact", contextContact | contextDraft | contextInbox | contextOutbox},
	{"download", downloadCommand{}, "Download a numbered detachment to disk", contextInbox},
	{"drafts", showDraftsSummaryCommand{}, "Show drafts", 0},
	{"edit", editCommand{}, "Edit the draft message", contextDraft},
	{"help", helpCommand{}, "List known commands", 0},
	{"identity", showIdentityCommand{}, "Show identity", 0},
	{"inbox", showInboxSummaryCommand{}, "Show the Inbox", 0},
	{"log", logCommand{}, "Show recent log entries", 0},
	{"new-contact", newContactCommand{}, "Start a key exchange with a new contact", 0},
	{"introduce", introduceContactCommand{}, "Introduce a contact to multiple contacts", contextContact},
	{"introgroup", introduceContactGroupCommand{}, "Introduce a group of contacts to one another", 0},
	{"greet", greetContactCommand{}, "Accept an introduction of a proposed new contact", contextInbox},
	{"outbox", showOutboxSummaryCommand{}, "Show the Outbox", 0},
	{"queue", showQueueStateCommand{}, "Show the queue", 0},
	{"quit", quitCommand{}, "Exit Pond", 0},
	{"remove", removeCommand{}, "Remove an attachment or detachment from a draft message", contextDraft},
	{"rename", renameCommand{}, "Rename an existing contact", contextContact},
	{"reply", replyCommand{}, "Reply to the current message", contextInbox},
	{"retain", retainCommand{}, "Retain the current message", contextInbox},
	{"dont-retain", dontRetainCommand{}, "Do not retain the current message", contextInbox},
	{"save", saveCommand{}, "Save a numbered attachment to disk", contextInbox},
	{"save-key", saveKeyCommand{}, "Save the key to a detachment to disk", contextInbox},
	{"send", sendCommand{}, "Send the current draft", contextDraft},
	{"show", showCommand{}, "Show the current object", contextDraft | contextInbox | contextOutbox | contextContact},
	{"status", statusCommand{}, "Show overall Pond status", 0},
	{"transact-now", transactNowCommand{}, "Perform a network transaction now", 0},
	{"upload", uploadCommand{}, "Upload a file to home server and include key in current draft", contextDraft},
}

type abortCommand struct{}
type ackCommand struct{}
type clearCommand struct{}
type closeCommand struct{}
type composeCommand struct{}
type deleteCommand struct{}
type editCommand struct{}
type logCommand struct{}
type quitCommand struct{}
type replyCommand struct{}
type retainCommand struct{}
type dontRetainCommand struct{}
type sendCommand struct{}
type showCommand struct{}
type showContactsCommand struct{}
type showDraftsSummaryCommand struct{}
type showIdentityCommand struct{}
type showInboxSummaryCommand struct{}
type showOutboxSummaryCommand struct{}
type showQueueStateCommand struct{}
type statusCommand struct{}
type transactNowCommand struct{}

type newContactCommand struct {
	Name string
}

type introduceContactCommand struct {}
type introduceContactGroupCommand struct {}

type greetContactCommand struct {
	Index string
}

type renameCommand struct {
	NewName string
}

type attachCommand struct {
	Filename string `cli:"filename"`
}

type uploadCommand struct {
	Filename string `cli:"filename"`
}

type saveCommand struct {
	Number   string
	Filename string `cli:"filename"`
}

type saveKeyCommand struct {
	Number   string
	Filename string `cli:"filename"`
}

type downloadCommand struct {
	Number   string
	Filename string `cli:"filename"`
}

type removeCommand struct {
	Number string
}

type tagCommand struct {
	tag string
}

type helpCommand struct {
	ShowAll bool `flag:all`
}

func numPositionalFields(t reflect.Type) int {
	for i := 0; i < t.NumField(); i++ {
		if strings.HasPrefix(string(t.Field(i).Tag), "flag:") {
			return i
		}
	}
	return t.NumField()
}

func parseCommandForCompletion(commands []cliCommand, line string) (before, prefix string, isCommand, ok bool) {
	if len(line) == 0 {
		return
	}

	spacePos := strings.IndexRune(line, ' ')
	if spacePos == -1 {
		// We're completing a command or tag name.
		prefix = line
		isCommand = true
		ok = true
		return
	}

	command := line[:spacePos]
	var prototype interface{}

	for _, cmd := range commands {
		if cmd.name == command {
			prototype = cmd.prototype
			break
		}
	}
	if prototype == nil {
		return
	}

	t := reflect.TypeOf(prototype)
	fieldNum := -1
	fieldStart := 0
	inQuotes := false
	lastWasEscape := false
	numFields := numPositionalFields(t)

	skippingWhitespace := true
	for pos, r := range line[spacePos:] {
		if skippingWhitespace {
			if r == ' ' {
				continue
			}
			skippingWhitespace = false
			fieldNum++
			fieldStart = pos + spacePos
		}

		if lastWasEscape {
			lastWasEscape = false
			continue
		}

		if r == '\\' {
			lastWasEscape = true
			continue
		}

		if r == '"' {
			inQuotes = !inQuotes
		}

		if r == ' ' && !inQuotes {
			skippingWhitespace = true
		}
	}

	if skippingWhitespace {
		return
	}
	if fieldNum >= numFields {
		return
	}
	f := t.Field(fieldNum)
	if f.Tag.Get("cli") != "filename" {
		return
	}
	ok = true
	isCommand = false
	before = line[:fieldStart]
	prefix = line[fieldStart:]
	return
}

// setOption updates the cliCommand, v, of type t given an option string with
// the "--" prefix already removed. It returns true on success.
func setOption(v reflect.Value, t reflect.Type, option string) bool {
	for i := 0; i < t.NumField(); i++ {
		fieldType := t.Field(i)
		tag := string(fieldType.Tag)
		if strings.HasPrefix(tag, "flag:") && tag[5:] == option {
			field := v.Field(i)
			if field.Bool() {
				return false // already set
			} else {
				field.SetBool(true)
				return true
			}
		}
	}

	return false
}

func parseCommand(commands []cliCommand, line []byte) (interface{}, string) {
	spacePos := bytes.IndexByte(line, ' ')
	if spacePos == -1 {
		spacePos = len(line)
	}
	command := string(line[:spacePos])
	var prototype interface{}

	for _, cmd := range commands {
		if cmd.name == command {
			prototype = cmd.prototype
			break
		}
	}
	if prototype == nil {
		if len(command) == 0 || len(command) == 3 {
			// Very likely a tag or a blank line.
			return tagCommand{string(line)}, ""
		}
		return nil, "Unknown command: " + command
	}

	t := reflect.TypeOf(prototype)
	v := reflect.New(t)
	v = reflect.Indirect(v)
	pos := spacePos
	fieldNum := -1
	inQuotes := false
	lastWasEscape := false
	numFields := numPositionalFields(t)
	var field []byte

	skippingWhitespace := true
	for ; pos <= len(line); pos++ {
		if !skippingWhitespace && (pos == len(line) || (line[pos] == ' ' && !inQuotes && !lastWasEscape)) {
			skippingWhitespace = true
			strField := string(field)

			switch {
			case fieldNum < numFields:
				f := v.Field(fieldNum)
				f.Set(reflect.ValueOf(strField))
			case strings.HasPrefix(strField, "--"):
				if !setOption(v, t, strField[2:]) {
					return nil, "No such option " + strField + " for command"
				}
			default:
				return nil, "Too many arguments for command " + command + ". Expected " + strconv.Itoa(v.NumField())
			}
			field = field[:0]
			continue
		}

		if pos == len(line) {
			break
		}

		if lastWasEscape {
			field = append(field, line[pos])
			lastWasEscape = false
			continue
		}

		if skippingWhitespace {
			if line[pos] == ' ' {
				continue
			}
			skippingWhitespace = false
			fieldNum++
		}

		if line[pos] == '\\' {
			lastWasEscape = true
			continue
		}

		if line[pos] == '"' {
			inQuotes = !inQuotes
			continue
		}

		field = append(field, line[pos])
	}

	if fieldNum < numFields-1 {
		return nil, "Too few arguments for command " + command + ". Expected " + strconv.Itoa(v.NumField()) + ", but found " + strconv.Itoa(fieldNum+1)
	}

	return v.Interface(), ""
}

type cliInput struct {
	term                 *terminal.Terminal
	commands             *priorityList
	lastKeyWasCompletion bool
}

type cliTerminalLine struct {
	command interface{}
	err     error
	ackChan chan struct{}
}

func (i *cliInput) processInput(commandsChan chan<- cliTerminalLine) {
	i.commands = new(priorityList)
	for _, command := range cliCommands {
		i.commands.Insert(command.name)
	}

	autoCompleteCallback := func(line string, pos int, key rune) (string, int, bool) {
		return i.AutoComplete(line, pos, key)
	}

	i.term.AutoCompleteCallback = autoCompleteCallback

	var ackChan chan struct{}

	for {
		if ackChan != nil {
			<-ackChan
		}
		ackChan = make(chan struct{})

		line, err := i.term.ReadLine()
		if err != nil {
			commandsChan <- cliTerminalLine{err: err, ackChan: ackChan}
			continue
		}
		cmd, errStr := parseCommand(cliCommands, []byte(line))
		if len(errStr) != 0 {
			fmt.Fprintf(i.term, "%s %s\n", termWarnPrefix, errStr)
			ackChan = nil
			continue
		}
		if cmd != nil {
			commandsChan <- cliTerminalLine{command: cmd, ackChan: ackChan}
		}
		continue
	}
}

func (input *cliInput) showHelp(context inputContext, showAll bool) {
	contextTable := cliTable{
		heading:      "These commands operate on the current object:",
		noIndicators: true,
	}
	globalTable := cliTable{
		heading:      "These commands are global:",
		noIndicators: true,
	}

	if showAll {
		globalTable.heading = "All commands:"
	}

	for _, cmd := range cliCommands {
		if !showAll && cmd.context != 0 && context&cmd.context == 0 {
			continue
		}

		line := cmd.name
		prototype := reflect.TypeOf(cmd.prototype)
		for j := 0; j < prototype.NumField(); j++ {
			if strings.HasPrefix(string(prototype.Field(j).Tag), "flag:") {
				line += " [--" + strings.ToLower(string(prototype.Field(j).Tag[5:])) + "]"
			} else {
				line += " <" + strings.ToLower(prototype.Field(j).Name) + ">"
			}
		}

		table := &globalTable
		if context&cmd.context != 0 {
			table = &contextTable
		}
		table.rows = append(table.rows, cliRow{
			cols: []string{line, cmd.desc},
		})
	}

	widths := globalTable.UpdateWidths(contextTable.UpdateWidths(nil))
	globalTable.WriteToWithWidths(input.term, widths)
	if len(contextTable.rows) > 0 {
		contextTable.WriteToWithWidths(input.term, widths)
	}
}

func pathComplete(path string) (completedPath string, isComplete, ok bool) {
	quoted := len(path) > 0 && path[0] == '"'
	if quoted {
		path = path[1:]
		if len(path) > 0 && path[len(path)-1] == '"' {
			path = path[:len(path)-1]
		}
	}

	if strings.HasPrefix(path, "~/") {
		if home := os.Getenv("HOME"); len(home) > 0 {
			path = filepath.Join(home, path[2:])
		}
	}
	path = filepath.Clean(path)
	dirName := filepath.Dir(path)
	base := filepath.Base(path)

	dir, err := os.Open(dirName)
	if err != nil {
		return "", false, false
	}
	defer dir.Close()

	ents, err := dir.Readdirnames(-1)
	if err != nil {
		return "", false, false
	}

	var candidates []string
	for _, ent := range ents {
		if strings.HasPrefix(ent, base) {
			candidates = append(candidates, ent)
		}
	}
	switch len(candidates) {
	case 0:
		return "", false, false
	case 1:
		completedPath = filepath.Join(dirName, candidates[0])
		quoted = quoted || strings.IndexRune(candidates[0], ' ') != -1
		fi, err := os.Stat(completedPath)
		if quoted {
			completedPath = "\"" + completedPath
		}
		if err == nil && fi.IsDir() {
			return completedPath + "/", false, true
		}
		if quoted {
			completedPath += "\""
		}
		return completedPath, true, true
	}

	sort.Strings(candidates)
	first := []rune(candidates[0])
	last := []rune(candidates[len(candidates)-1])

	for i, r := range first {
		if last[i] != r {
			completedPath = filepath.Join(dirName, string(first[:i]))
			if quoted {
				completedPath = "\"" + completedPath
			}
			return completedPath, false, true
		}
		if last[i] == ' ' {
			quoted = true
		}
	}

	// Duplicate entries in the directory?
	return filepath.Join(dirName, candidates[0]), true, true
}

func (i *cliInput) AutoComplete(line string, pos int, key rune) (string, int, bool) {
	const keyTab = 9

	if key != keyTab {
		i.lastKeyWasCompletion = false
		return "", -1, false
	}

	prefix := line[:pos]
	if i.lastKeyWasCompletion {
		// The user hit tab right after a completion, so we got
		// it wrong.
		if strings.IndexRune(prefix, ' ') == len(prefix)-1 {
			// We just completed a command.
			newCommand := i.commands.Next()
			newLine := string(newCommand) + " " + line[pos:]
			return newLine, len(newCommand) + 1, true
		}
	} else {
		if len(prefix) > 0 {
			a, b, isCommand, ok := parseCommandForCompletion(cliCommands, prefix)
			if !ok {
				return "", -1, false
			}
			var newValue string
			var spacer string
			if isCommand {
				newValue, ok = i.commands.Find(b)
				spacer = " "
			} else {
				var complete bool
				newValue, complete, ok = pathComplete(b)
				if complete {
					spacer = " "
				}
			}
			if !ok {
				return "", -1, false
			}

			newLine := string(a) + newValue + spacer + line[pos:]
			i.lastKeyWasCompletion = true
			return newLine, len(a) + len(newValue) + len(spacer), true
		}
	}

	i.lastKeyWasCompletion = false
	return "", -1, false
}

type priorityListEntry struct {
	value string
	next  *priorityListEntry
}

type priorityList struct {
	head       *priorityListEntry
	lastPrefix string
	lastResult string
	n          int
}

func (pl *priorityList) Insert(value string) {
	ent := new(priorityListEntry)
	ent.next = pl.head
	ent.value = value
	pl.head = ent
}

func (pl *priorityList) findNth(prefix string, nth int) (string, bool) {
	var cur, last *priorityListEntry
	cur = pl.head
	for n := 0; cur != nil; cur = cur.next {
		if strings.HasPrefix(cur.value, prefix) {
			if n == nth {
				// move this entry to the top
				if last != nil {
					last.next = cur.next
				} else {
					pl.head = cur.next
				}
				cur.next = pl.head
				pl.head = cur
				pl.lastResult = cur.value
				return cur.value, true
			}
			n++
		}
		last = cur
	}

	return "", false
}

func (pl *priorityList) Find(prefix string) (string, bool) {
	pl.lastPrefix = prefix
	pl.n = 0

	return pl.findNth(prefix, 0)
}

func (pl *priorityList) Next() string {
	pl.n++
	result, ok := pl.findNth(pl.lastPrefix, pl.n)
	if !ok {
		pl.n = 1
		result, ok = pl.findNth(pl.lastPrefix, pl.n)
	}
	// In this case, there's only one matching entry in the list.
	if !ok {
		pl.n = 0
		result, _ = pl.findNth(pl.lastPrefix, pl.n)
	}
	return result
}
