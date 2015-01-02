package main

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/agl/pond/client/disk"
	"github.com/golang/protobuf/proto"
)

func TestSerializedDeserialize(t *testing.T) {
	original, err := ioutil.ReadFile("testdata/stateproto")
	if err != nil {
		t.Fatalf("Failed to read stateproto: %s", err)
	}

	state := new(disk.State)
	if err := proto.Unmarshal(original, state); err != nil {
		t.Fatalf("Failed to parse stateproto: %s", err)
	}
	ioutil.WriteFile("a", []byte(proto.MarshalTextString(state)), 0600)

	var buffer bytes.Buffer
	entities := serialise(&buffer, state)
	textual := append([]byte(nil), buffer.Bytes()...)
	ioutil.WriteFile("text", []byte(textual), 0600)
	newState := new(disk.State)
	if err := parse(newState, &buffer, entities); err != nil {
		t.Fatalf("Failed to parse textual stateproto: %s", err)
	}

	buffer.Reset()
	serialise(&buffer, state)
	textual2 := buffer.Bytes()

	if !bytes.Equal(textual, textual2) {
	}

	result, err := proto.Marshal(newState)
	if err != nil {
		t.Fatalf("Failed to serialise new state: %s", err)
	}

	if !bytes.Equal(original, result) {
		ioutil.WriteFile("b", []byte(proto.MarshalTextString(newState)), 0600)
		t.Fatalf("Result does not equal original")
	}
}
