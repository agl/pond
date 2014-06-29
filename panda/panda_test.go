package panda

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestSerialise(t *testing.T) {
	secret := SharedSecret{
		Secret: "foo",
	}
	mp := NewSimpleMeetingPlace()
	kx, err := NewKeyExchange(rand.Reader, mp, &secret, []byte{1})
	if err != nil {
		t.Fatalf("failed to create KeyExchange: %s", err)
	}

	serialised := kx.Marshal()

	if _, err := UnmarshalKeyExchange(rand.Reader, mp, serialised); err != nil {
		t.Fatalf("UnmarshalKeyExchange failed: %s", err)
	}
}

func runKX(resultChan chan interface{}, log func(string, ...interface{}), mp MeetingPlace, secret *SharedSecret, message []byte) {
	kx, err := NewKeyExchange(rand.Reader, mp, secret, message)
	if err != nil {
		resultChan <- err
	}
	kx.Log = log
	kx.Testing = true
	reply, err := kx.Run()
	if err != nil {
		resultChan <- err
	}
	resultChan <- reply
}

func TestKeyExchange(t *testing.T) {
	a, b := make(chan interface{}), make(chan interface{})
	mp := NewSimpleMeetingPlace()
	secret := SharedSecret{
		Secret: "foo",
	}

	msg1 := []byte("test1")
	msg2 := []byte("test2")
	go runKX(a, t.Logf, mp, &secret, msg1)
	go runKX(b, t.Logf, mp, &secret, msg2)

	result := <-a
	if reply, ok := result.([]byte); ok {
		if !bytes.Equal(reply, msg2) {
			t.Errorf("Bad result from kx: got %x, want %x", reply, msg2)
		}
	} else {
		t.Errorf("Error from key exchange: %v", result)
	}

	result = <-b
	if reply, ok := result.([]byte); ok {
		if !bytes.Equal(reply, msg1) {
			t.Errorf("Bad result from kx: got %x, want %x", reply, msg1)
		}
	} else {
		t.Errorf("Error from key exchange: %s", result)
	}
}

func TestStartStop(t *testing.T) {
	mp := NewSimpleMeetingPlace()
	secret := SharedSecret{
		Secret: "foo",
	}

	msg1 := []byte("test1")
	msg2 := []byte("test2")
	a := make(chan interface{})
	go runKX(a, t.Logf, mp, &secret, msg1)

	panicLog := func(format string, args ...interface{}) {
		fmt.Printf(format, args...)
		t.Logf(format, args...)
		panic("unwind")
	}

	kx, err := NewKeyExchange(rand.Reader, mp, &secret, msg2)
	if err != nil {
		t.Fatal(err)
	}
	serialised := kx.Marshal()
	kx.Log = panicLog
	kx.Testing = true
	count := 0

	var result []byte
	done := false
	for !done {
		kx, err := UnmarshalKeyExchange(rand.Reader, mp, serialised)
		if err != nil {
			t.Fatalf("Failed to unmarshal KeyExchange: %s", err)
		}
		kx.Log = panicLog
		kx.Testing = true

		func() {
			defer func() {
				if count < 2 {
					serialised = kx.Marshal()
					recover()
				}
				count++
			}()
			result, err = kx.Run()
			if err != nil {
				t.Fatalf("Error from key exchange: %s", err)
			}
			done = true
		}()
	}

	if !bytes.Equal(result, msg1) {
		t.Errorf("Bad result from kx: got %x, want %x", result, msg1)
	}
}

func TestSecretStringGeneration(t *testing.T) {
	s := NewSecretString(rand.Reader)
	if !isValidSecretString(s) {
		t.Fatalf("Generated secret string isn't valid: %s", s)
	}
	if !IsAcceptableSecretString(s) {
		t.Fatalf("Generated secret string isn't acceptable: %s", s)
	}
	s = s[:8] + "," + s[9:]
	if isValidSecretString(s) {
		t.Fatalf("Corrupt secret string is valid: %s", s)
	}

	s = "498572384"
	if !IsAcceptableSecretString(s) {
		t.Fatalf("Random secret string isn't acceptable: %s", s)
	}
	if isValidSecretString(s) {
		t.Fatalf("Random secret string is valid: %s", s)
	}
}
