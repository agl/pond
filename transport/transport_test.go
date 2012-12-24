package transport

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"

	"code.google.com/p/go.crypto/curve25519"
	pond "github.com/agl/pond/protos"
)

func NewBiDiPipe() (x, y net.Conn) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		panic(err)
	}

	addr := listener.Addr().(*net.TCPAddr)
	client, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		panic(err)
	}

	server, err := listener.Accept()
	if err != nil {
		panic(err)
	}

	listener.Close()

	return client, server
}

func runHandshake(clientPrivate, clientPublic, serverPrivate, serverPublic *[32]byte) (error, error) {
	x, y := NewBiDiPipe()
	client := NewClient(x, clientPrivate, clientPublic, serverPublic)
	server := NewServer(y, serverPrivate)

	clientError := make(chan error, 1)
	go func() {
		defer x.Close()
		defer close(clientError)
		err := client.Handshake()
		if err == nil {
			err = client.WriteProto(&pond.Fetch{})
		}
		clientError <- err
	}()

	serverError := make(chan error, 1)
	go func() {
		defer y.Close()
		defer close(serverError)
		err := server.Handshake()
		if err == nil {
			if !bytes.Equal(server.Peer[:], clientPublic[:]) {
				err = errors.New("server's view of client's identity is incorrect")
			}
		}
		if err == nil {
			msg := new(pond.Fetch)
			err = server.ReadProto(msg)
		}
		serverError <- err
	}()

	err1 := <-clientError
	err2 := <-serverError
	return err1, err2
}

func TestHandshake(t *testing.T) {
	var serverPrivate, clientPrivate, serverPublic, clientPublic [32]byte

	if _, err := io.ReadFull(rand.Reader, serverPrivate[:]); err != nil {
		t.Fatalf("reading from rand: %s", err)
	}
	if _, err := io.ReadFull(rand.Reader, clientPrivate[:]); err != nil {
		t.Fatalf("reading from rand: %s", err)
	}

	curve25519.ScalarBaseMult(&serverPublic, &serverPrivate)
	curve25519.ScalarBaseMult(&clientPublic, &clientPrivate)

	clientError, serverError := runHandshake(&clientPrivate, &clientPublic, &serverPrivate, &serverPublic)
	if clientError != nil || serverError != nil {
		t.Fatalf("handshake failed: client:'%s' server:'%s'", clientError, serverError)
	}

	serverPublic[0] ^= 0x40
	clientError, serverError = runHandshake(&clientPrivate, &clientPublic, &serverPrivate, &serverPublic)
	if clientError == nil && serverError == nil {
		t.Fatal("bad handshake succeeded")
	}
}
