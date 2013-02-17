package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"reflect"
	"strings"

	"code.google.com/p/go.crypto/ssh/terminal"
	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/pond/client/disk"
	pond "github.com/agl/pond/protos"
)

var stateFile *string = flag.String("state-file", "state", "File in which to save persistent state")

func main() {
	flag.Parse()

	if !do() {
		os.Exit(1)
	}
}

func serialise(out io.Writer, state *disk.State) {
	serialiseStruct(out, reflect.ValueOf(*state), reflect.TypeOf(*state), "", 0)
}

func serialiseStruct(out io.Writer, v reflect.Value, t reflect.Type, context string, level uint) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Name == "XXX_unrecognized" {
			continue
		}
		fv := v.Field(i)

		switch f.Type.Kind() {
		case reflect.Slice:
			if f.Type.Elem().Kind() == reflect.Uint8 {
				serialiseValue(out, f.Name, fv, f.Type, context, level)
			} else {
				if f.Type.Elem().Kind() == reflect.Ptr {
					for i := 0; i < fv.Len(); i++ {
						serialiseValue(out, f.Name, fv.Index(i).Elem(), f.Type.Elem().Elem(), context, level)
					}
				} else {
					for i := 0; i < fv.Len(); i++ {
						serialiseValue(out, f.Name, fv.Index(i), f.Type.Elem(), context, level)
					}
				}
			}
		case reflect.Ptr:
			if !fv.IsNil() {
				serialiseValue(out, f.Name, fv.Elem(), f.Type.Elem(), context, level)
			}
		default:
			fmt.Printf("%s %v\n", f.Name, fv)
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

func serialiseValue(out io.Writer, name string, v reflect.Value, t reflect.Type, context string, level uint) {
	if context == "Outbox" && name == "Request" {
		return
	}
	if t.Kind() == reflect.Slice && (context == "Outbox" || context == "Inbox") && name == "Message" {
		var msg pond.Message
		if err := proto.Unmarshal(v.Bytes(), &msg); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to unmarshal Message: %s\n", err)
			panic("deserialisation error")
		}
		v = reflect.ValueOf(msg)
		serialiseValue(out, name, v, v.Type(), context, level)
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
		raw := v.Bytes()
		encoded := make([]byte, hex.EncodedLen(len(raw)))
		hex.Encode(encoded, raw)
		out.Write(encoded)
	case reflect.Bool:
		out.Write(valueSep)
		fmt.Fprintf(out, "%t", v.Bool())
	case reflect.String:
		s := v.String()
		if strings.ContainsRune(s, '\n') || name == "Body" {
			delim := rand.Int63()
			fmt.Fprintf(out, "<<%x\n", delim)
			out.Write([]byte(s))
			fmt.Fprintf(out, "\n--%x", delim)
		} else {
			out.Write(valueSep)
			fmt.Fprintf(out, "\"%s\"", escapeString(v.String()))
		}
	case reflect.Uint32, reflect.Uint64:
		out.Write(valueSep)
		fmt.Fprintf(out, "%d", v.Uint())
	case reflect.Int64:
		out.Write(valueSep)
		fmt.Fprintf(out, "%d", v.Int())
	case reflect.Struct:
		out.Write(structSep)
		newContext := context
		if len(newContext) > 0 {
			newContext += "."
		}
		newContext += name
		serialiseStruct(out, v, t, newContext, level+1)
		for i := uint(0); i < level; i++ {
			out.Write(levelMark)
		}
		out.Write(structEnd)
	}
	fmt.Fprintf(out, "\n")
}

func do() bool {
	encrypted, err := ioutil.ReadFile(*stateFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read state file: %s\n", err)
		return false
	}

	salt, ok := disk.GetSCryptSaltFromState(encrypted)
	if !ok {
		fmt.Fprintf(os.Stderr, "State file is too short to be valid\n")
		return false
	}

	var state *disk.State
	var key [32]byte

	for {
		state, err = disk.LoadState(encrypted, &key)
		if err == nil {
			break
		}
		if err != disk.BadPasswordError {
			fmt.Fprintf(os.Stderr, "Failed to decrypt state file: %s\n", err)
			return false
		}

		fmt.Fprintf(os.Stderr, "Passphrase: ")
		password, err := terminal.ReadPassword(0)
		fmt.Fprintf(os.Stderr, "\n")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read password\n")
			return false
		}
		keySlice, err := disk.DeriveKey(string(password), &salt)
		copy(key[:], keySlice)
	}

	serialise(os.Stdout, state)
	return true
}
