package main

import (
	"bytes"
	crypto_rand "crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"syscall"

	"github.com/agl/pond/client/disk"
	"github.com/agl/pond/client/system"
	pond "github.com/agl/pond/protos"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	stateFileName *string = flag.String("state-file", "state", "File in which to save persistent state")
	skipChecks    *bool   = flag.Bool("skip-checks", false, "If true, system sanity checks are skipped")
)

func main() {
	flag.Parse()

	if !do() {
		os.Exit(1)
	}
}

func serialise(out io.Writer, state *disk.State) map[uint32][]byte {
	entities := make(map[uint32][]byte)
	serialiseStruct(out, reflect.ValueOf(*state), reflect.TypeOf(*state), "", 0, entities)
	return entities
}

func serialiseStruct(out io.Writer, v reflect.Value, t reflect.Type, context string, level uint, entities map[uint32][]byte) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Name == "XXX_unrecognized" {
			continue
		}
		fv := v.Field(i)

		switch f.Type.Kind() {
		case reflect.Slice:
			if f.Type.Elem().Kind() == reflect.Uint8 {
				serialiseValue(out, f.Name, fv, f.Type, context, level, entities)
			} else {
				if f.Type.Elem().Kind() == reflect.Ptr {
					for i := 0; i < fv.Len(); i++ {
						serialiseValue(out, f.Name, fv.Index(i).Elem(), f.Type.Elem().Elem(), context, level, entities)
					}
				} else {
					for i := 0; i < fv.Len(); i++ {
						serialiseValue(out, f.Name, fv.Index(i), f.Type.Elem(), context, level, entities)
					}
				}
			}
		case reflect.Ptr:
			if !fv.IsNil() {
				serialiseValue(out, f.Name, fv.Elem(), f.Type.Elem(), context, level, entities)
			}
		default:
			panic(fmt.Sprintf("Don't know how to serialize %s", f))
		}
	}
}

func escapeString(in string) string {
	return strings.Replace(strings.Replace(in, "\\", "\\\\", -1), "\"", "\\\"", -1)
}

var valueSep = []byte(": ")
var structSep = []byte(" <\n")
var structEnd = []byte(">")
var levelMark = []byte("\t")

func contextAppend(context, extra string) string {
	if len(context) > 0 {
		context += "."
	}
	context += extra
	return context
}

func setEntity(entities map[uint32][]byte, data []byte) uint32 {
	table := crc32.MakeTable(crc32.Castagnoli)
	crc := crc32.Checksum(data, table)
	for {
		other, ok := entities[crc]
		if !ok {
			entities[crc] = data
			return crc
		}
		if bytes.Equal(other, data) {
			return crc
		}
		crc++
	}

	panic("unreachable")
}

func serialiseValue(out io.Writer, name string, v reflect.Value, t reflect.Type, context string, level uint, entities map[uint32][]byte) {
	if t.Kind() == reflect.Slice && (context == "Outbox" || context == "Inbox") && name == "Message" {
		var msg pond.Message
		if err := proto.Unmarshal(v.Bytes(), &msg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to unmarshal Message: %s\n", err)
			fmt.Fprintf(out, "BAD MESSAGE: \"%x\"\n", v.Bytes())
			return
		}
		v = reflect.ValueOf(msg)
		serialiseValue(out, name, v, v.Type(), context, level, entities)
		return
	}
	if t.Kind() == reflect.Slice && (context == "Inbox.Message" || context == "Outbox.Message") && name == "Body" {
		s := string(v.Bytes())
		v = reflect.ValueOf(s)
		t = v.Type()
	}
	for i := uint(0); i < level; i++ {
		out.Write(levelMark)
	}
	out.Write([]byte(name))
	switch t.Kind() {
	case reflect.Slice:
		// This must be a byte slice.
		out.Write(valueSep)
		if context == "Outbox" && name == "Request" ||
			context == "Outbox.Message.Files" && name == "Contents" ||
			context == "Inbox.Message.Files" && name == "Contents" {
			entityName := setEntity(entities, v.Bytes())
			fmt.Fprintf(out, "<%x>", entityName)
		} else {
			raw := v.Bytes()
			if len(raw) == 0 {
				out.Write([]byte("\"\""))
			} else {
				encoded := make([]byte, hex.EncodedLen(len(raw)))
				hex.Encode(encoded, raw)
				out.Write(encoded)
			}
		}
	case reflect.Bool:
		out.Write(valueSep)
		fmt.Fprintf(out, "%t", v.Bool())
	case reflect.String:
		s := v.String()
		out.Write(valueSep)
		if strings.ContainsRune(s, '\n') || name == "Body" {
			delim := rand.Int63()
			fmt.Fprintf(out, "<<%x\n", delim)
			out.Write([]byte(s))
			fmt.Fprintf(out, "--%x", delim)
		} else {
			fmt.Fprintf(out, "\"%s\"", escapeString(v.String()))
		}
	case reflect.Uint32, reflect.Uint64:
		out.Write(valueSep)
		fmt.Fprintf(out, "%d", v.Uint())
	case reflect.Int32, reflect.Int64:
		out.Write(valueSep)
		fmt.Fprintf(out, "%d", v.Int())
	case reflect.Struct:
		out.Write(structSep)
		serialiseStruct(out, v, t, contextAppend(context, name), level+1, entities)
		for i := uint(0); i < level; i++ {
			out.Write(levelMark)
		}
		out.Write(structEnd)
	default:
		panic(fmt.Sprintf("Don't know how to serialise a %s", t))
	}
	fmt.Fprintf(out, "\n")
}

func parse(state *disk.State, in io.Reader, entities map[uint32][]byte) error {
	tokenizer := NewTokenizer(in)
	v := reflect.ValueOf(state).Elem()
	t := reflect.TypeOf(state).Elem()
	for {
		fieldName, err := tokenizer.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if err := parseStructField(v, t, "", fieldName, tokenizer, entities); err != nil {
			return err
		}
	}
	return nil
}

func parseStruct(v reflect.Value, t reflect.Type, context string, in *Tokenizer, entities map[uint32][]byte) error {
	for {
		fieldName, err := in.Next()
		if err != nil {
			return err
		}
		if fieldName == ">" {
			return nil
		}
		if err := parseStructField(v, t, context, fieldName, in, entities); err != nil {
			return err
		}
	}

	panic("unreachable")
}

func parseStructField(v reflect.Value, t reflect.Type, context, fieldName string, in *Tokenizer, entities map[uint32][]byte) error {
	f, ok := t.FieldByName(fieldName)
	if !ok {
		return fmt.Errorf("line %d: unknown field '%s'", in.Line, fieldName)
	}

	fv := v.FieldByName(fieldName)

	sep, err := in.Next()
	if err != nil {
		return err
	}

	fieldIsProtobuf := false
	var protobufType reflect.Type
	switch f.Type.Kind() {
	case reflect.Ptr:
		fieldIsProtobuf = f.Type.Elem().Kind() == reflect.Struct
		if fieldIsProtobuf {
			protobufType = f.Type.Elem()
		}
	case reflect.Slice:
		fieldIsProtobuf = f.Type.Elem().Kind() == reflect.Ptr &&
			f.Type.Elem().Elem().Kind() == reflect.Struct
		if fieldIsProtobuf {
			protobufType = f.Type.Elem().Elem()
		}
	}

	switch sep {
	case "<":
		// Must be a protocol buffer or a slice of them.
		isSerialized := false
		if (context == "Inbox" || context == "Outbox") && fieldName == "Message" {
			// These aren't protobufs in the structure - they need
			// to be written as a []byte.
			isSerialized = true
			var msg pond.Message
			protobufType = reflect.TypeOf(msg)
		} else {
			if !fieldIsProtobuf {
				return fmt.Errorf("line %d: field %s is not a protobuf, it's a %s", in.Line, fieldName, f.Type)
			}
		}
		value := reflect.New(protobufType)
		if err := parseStruct(value.Elem(), value.Type().Elem(), contextAppend(context, fieldName), in, entities); err != nil {
			return err
		}

		if isSerialized {
			serialized, err := proto.Marshal(value.Interface().(proto.Message))
			if err != nil {
				return fmt.Errorf("line %d: error serialising protobuf: %s", in.Line, err)
			}
			fv.SetBytes(serialized)
		} else {
			switch f.Type.Kind() {
			case reflect.Ptr:
				fv.Set(value)
			case reflect.Slice:
				fv.Set(reflect.Append(fv, value))
			default:
				panic("impossible")
			}
		}
	case ":":
		if fieldIsProtobuf {
			return fmt.Errorf("line %d: field is protobuf, but found ':'", in.Line)
		}
		if err := parseValue(fv, f, contextAppend(context, fieldName), in, entities); err != nil {
			return err
		}
	default:
		return fmt.Errorf("line %d: unexpected '%s'", in.Line, sep)
	}

	return nil
}

func parseValue(v reflect.Value, t reflect.StructField, context string, in *Tokenizer, entities map[uint32][]byte) error {
	token, err := in.Next()
	if err != nil {
		return err
	}

	switch t.Type.Kind() {
	case reflect.Ptr:
		switch t.Type.Elem().Kind() {
		case reflect.String:
			s := reflect.New(t.Type.Elem())
			s.Elem().SetString(token)
			v.Set(s)
		case reflect.Uint32:
			value, err := strconv.ParseUint(token, 10, 32)
			if err != nil {
				return fmt.Errorf("line %d: cannot parse uint32: %s", in.Line, err)
			}
			i := reflect.New(t.Type.Elem())
			i.Elem().SetUint(value)
			v.Set(i)
		case reflect.Uint64:
			value, err := strconv.ParseUint(token, 10, 64)
			if err != nil {
				return fmt.Errorf("line %d: cannot parse uint64: %s", in.Line, err)
			}
			i := reflect.New(t.Type.Elem())
			i.Elem().SetUint(value)
			v.Set(i)
		case reflect.Int32:
			value, err := strconv.ParseInt(token, 10, 32)
			if err != nil {
				return fmt.Errorf("line %d: cannot parse int32: %s", in.Line, err)
			}
			i := reflect.New(t.Type.Elem())
			i.Elem().SetInt(value)
			v.Set(i)
		case reflect.Int64:
			value, err := strconv.ParseInt(token, 10, 64)
			if err != nil {
				return fmt.Errorf("line %d: cannot parse int64: %s", in.Line, err)
			}
			i := reflect.New(t.Type.Elem())
			i.Elem().SetInt(value)
			v.Set(i)
		case reflect.Bool:
			b := reflect.New(t.Type.Elem())
			switch token {
			case "true":
				b.Elem().SetBool(true)
			case "false":
				b.Elem().SetBool(false)
			default:
				return fmt.Errorf("line %d: boolean values must be 'true' or 'false', not %s", in.Line, token)
			}
			v.Set(b)
		default:
			return fmt.Errorf("line %d: unhandled type: pointer to %s", in.Line, t.Type.Elem())
		}
	case reflect.Slice:
		switch t.Type.Elem().Kind() {
		case reflect.Uint8:
			var value []byte
			alwaysSet := false

			if token == "<" {
				entityToken, err := in.Next()
				if err != nil {
					return err
				}
				entity, err := strconv.ParseUint(entityToken, 16, 32)
				if err != nil {
					return fmt.Errorf("line %d: failed to parse entity token: %s", in.Line, err)
				}
				endToken, err := in.Next()
				if err != nil {
					return err
				}
				if endToken != ">" {
					return fmt.Errorf("line %d: entity should have ended with '>'", in.Line)
				}

				var ok bool
				value, ok = entities[uint32(entity)]
				if !ok {
					return fmt.Errorf("line %d: unknown entity id", in.Line)
				}
			} else if context == "Inbox.Message.Body" || context == "Outbox.Message.Body" {
				value = []byte(token)
				alwaysSet = true
			} else {
				value, err = hex.DecodeString(token)
				if err != nil {
					return fmt.Errorf("line %d: failed to parse hex value: %s", in.Line, err)
				}
			}
			if len(value) > 0 || alwaysSet {
				v.SetBytes(value)
			}
		default:
			return fmt.Errorf("line %d: unhandled type: slice of %s", in.Line, t.Type.Elem())
		}
	default:
		return fmt.Errorf("line %d: unhandled type %s", in.Line, t.Type)
	}

	return nil
}

func do() bool {
	if !*skipChecks {
		if err := system.IsSafe(); err != nil {
			fmt.Fprintf(os.Stderr, "System checks failed: %s\n", err)
			return false
		}
	}

	editor := os.Getenv("EDITOR")
	if len(editor) == 0 {
		fmt.Fprintf(os.Stderr, "$EDITOR is not set\n")
		return false
	}

	stateFile := &disk.StateFile{
		Path: *stateFileName,
		Rand: crypto_rand.Reader,
		Log: func(format string, args ...interface{}) {
			fmt.Fprintf(os.Stderr, format, args...)
		},
	}

	stateLock, err := stateFile.Lock(false /* don't create */)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open state file: %s\n", err)
		return false
	}
	if stateLock == nil {
		fmt.Fprintf(os.Stderr, "Cannot obtain lock on state file\n")
		return false
	}
	defer stateLock.Close()

	var state *disk.State
	var passphrase string
	for {
		state, err = stateFile.Read(passphrase)
		if err == nil {
			break
		}
		if err != disk.BadPasswordError {
			fmt.Fprintf(os.Stderr, "Failed to decrypt state file: %s\n", err)
			return false
		}

		fmt.Fprintf(os.Stderr, "Passphrase: ")
		passphraseBytes, err := terminal.ReadPassword(0)
		fmt.Fprintf(os.Stderr, "\n")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read password\n")
			return false
		}
		passphrase = string(passphraseBytes)
	}

	tempDir, err := system.SafeTempDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get safe temp directory: %s\n", err)
		return false
	}

	tempFile, err := ioutil.TempFile(tempDir, "pond-editstate-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create temp file: %s\n", err)
		return false
	}
	tempFileName := tempFile.Name()
	defer func() {
		os.Remove(tempFileName)
	}()

	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		println("Caught signal: removing", tempFileName)
		os.Remove(tempFileName)
		os.Exit(1)
	}()

	entities := serialise(tempFile, state)

	var newStateSerialized []byte
	for {
		cmd := exec.Command(editor, tempFileName)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to run editor: %s\n", err)
			return false
		}
		tempFile.Close()
		tempFile, err := os.Open(tempFileName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open temp file: %s\n", err)
			return false
		}

		newState := new(disk.State)
		err = parse(newState, tempFile, entities)
		if err == nil {
			newStateSerialized, err = proto.Marshal(newState)
		}
		if err == nil {
			break
		}

		fmt.Fprintf(os.Stderr, "Error parsing: %s\n", err)
		fmt.Fprintf(os.Stderr, "Hit enter to edit again, or Ctrl-C to abort\n")

		var buf [100]byte
		os.Stdin.Read(buf[:])
	}

	states := make(chan disk.NewState)
	done := make(chan struct{})
	go stateFile.StartWriter(states, done)
	states <- disk.NewState{
		State:                newStateSerialized,
		RotateErasureStorage: false,
		Destruct:             false,
	}
	close(states)
	<-done

	return true
}
