package main

import (
	"bytes"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"code.google.com/p/go.crypto/ssh/terminal"
)

type cliCommand struct {
	name      string
	prototype interface{}
	desc      string
}

var cliCommands = []cliCommand{
	{"compose", composeCommand{}, "Compose a new message"},
	{"help", helpCommand{}, "List known commands"},
}

type composeCommand struct {
	To string "contact"
}

type helpCommand struct{}

type tagCommand struct {
	tag string
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
	if len(line) == 0 || line[0] != '/' {
		return
	}

	spacePos := strings.IndexRune(line, ' ')
	if spacePos == -1 {
		// We're completing a command name.
		before = line[:1]
		prefix = line[1:]
		isCommand = true
		ok = true
		return
	}

	command := line[1:spacePos]
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
	if f.Tag != "contact" {
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
	if len(line) == 0 || line[0] != '/' {
		panic("not a command")
	}

	spacePos := bytes.IndexByte(line, ' ')
	if spacePos == -1 {
		spacePos = len(line)
	}
	command := string(line[1:spacePos])
	var prototype interface{}

	for _, cmd := range commands {
		if cmd.name == command {
			prototype = cmd.prototype
			break
		}
	}
	if prototype == nil {
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
	contactComplete      *priorityList
	contactNames         []string
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

	i.contactComplete = new(priorityList)
	for _, contactName := range i.contactNames {
		i.contactComplete.Insert(contactName)
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
		if len(line) == 0 {
			ackChan = nil
			continue
		}
		if line[0] == '/' {
			cmd, err := parseCommand(cliCommands, []byte(line))
			if len(err) != 0 {
				fmt.Fprintf(i.term, "%s %s\n", termWarnPrefix, err)
				ackChan = nil
				continue
			}
			if _, ok := cmd.(helpCommand); ok {
				i.showHelp()
				ackChan = nil
				continue
			}
			if cmd != nil {
				commandsChan <- cliTerminalLine{command: cmd, ackChan: ackChan}
			}
			continue
		}

		commandsChan <- cliTerminalLine{command: tagCommand{string(line)}, ackChan: ackChan}
	}
}

func (input *cliInput) showHelp() {
	examples := make([]string, len(cliCommands))
	maxLen := 0

	for i, cmd := range cliCommands {
		line := "/" + cmd.name
		prototype := reflect.TypeOf(cmd.prototype)
		for j := 0; j < prototype.NumField(); j++ {
			if strings.HasPrefix(string(prototype.Field(j).Tag), "flag:") {
				line += " [--" + strings.ToLower(string(prototype.Field(j).Tag[5:])) + "]"
			} else {
				line += " <" + strings.ToLower(prototype.Field(j).Name) + ">"
			}
		}
		if l := len(line); l > maxLen {
			maxLen = l
		}
		examples[i] = line
	}

	for i, cmd := range cliCommands {
		line := examples[i]
		numSpaces := 1 + (maxLen - len(line))
		for j := 0; j < numSpaces; j++ {
			line += " "
		}
		line += cmd.desc
		fmt.Fprintf(input.term, "%s %s\n", termInfoPrefix, line)
	}
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
		if len(prefix) > 0 && prefix[0] == '/' {
			if strings.IndexRune(prefix, ' ') == len(prefix)-1 {
				// We just completed a command.
				newCommand := i.commands.Next()
				newLine := "/" + string(newCommand) + " " + line[pos:]
				return newLine, len(newCommand) + 2, true
			} else if prefix[len(prefix)-1] == ' ' {
				// We just completed a uid in a command.
				newUser := i.contactComplete.Next()
				spacePos := strings.LastIndex(prefix[:len(prefix)-1], " ")

				newLine := prefix[:spacePos] + " " + string(newUser) + " " + line[pos:]
				return newLine, spacePos + 1 + len(newUser) + 1, true
			}
		}
	} else {
		if len(prefix) > 0 && prefix[0] == '/' {
			a, b, isCommand, ok := parseCommandForCompletion(cliCommands, prefix)
			if !ok {
				return "", -1, false
			}
			var newValue string
			if isCommand {
				newValue, ok = i.commands.Find(b)
			} else {
				newValue, ok = i.contactComplete.Find(b)
			}
			if !ok {
				return "", -1, false
			}

			newLine := string(a) + newValue + " " + line[pos:]
			i.lastKeyWasCompletion = true
			return newLine, len(a) + len(newValue) + 1, true
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
