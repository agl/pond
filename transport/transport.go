package transport

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"strconv"
	"time"

	pond "github.com/agl/pond/protos"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"
)

// blockSize is the size of the blocks of data that we'll send and receive when
// working in streaming mode. Each block is prefixed by two length bytes (which
// aren't counted in blockSize) and includes secretbox.Overhead bytes of MAC
// tag (which are).
const blockSize = 4096 - 2

type Conn struct {
	conn                     io.ReadWriteCloser
	isServer                 bool
	identity, identityPublic [32]byte
	Peer                     [32]byte

	writeKey, readKey           [32]byte
	writeKeyValid, readKeyValid bool
	writeSequence, readSequence [24]byte

	// readBuffer is used to receive bytes from the network when this Conn
	// is used to stream data.
	readBuffer []byte
	// decryptBuffer is used to store decrypted payloads when this Conn is
	// used to stream data and the caller's buffer isn't large enough to
	// decrypt into directly.
	decryptBuffer []byte
	// readPending aliases into decryptBuffer when a partial decryption had
	// to be returned to a caller because of buffer size limitations.
	readPending []byte

	// writeBuffer is used to hold encrypted payloads when this Conn is
	// used for streaming data.
	writeBuffer []byte
}

func NewServer(conn io.ReadWriteCloser, identity *[32]byte) *Conn {
	c := &Conn{
		conn:     conn,
		isServer: true,
	}
	copy(c.identity[:], identity[:])
	return c
}

func NewClient(conn io.ReadWriteCloser, myIdentity, myIdentityPublic, serverPublic *[32]byte) *Conn {
	c := &Conn{
		conn: conn,
	}
	copy(c.identity[:], myIdentity[:])
	copy(c.identityPublic[:], myIdentityPublic[:])
	copy(c.Peer[:], serverPublic[:])
	return c
}

func incSequence(seq *[24]byte) {
	n := uint32(1)

	for i := 0; i < 8; i++ {
		n += uint32(seq[i])
		seq[i] = byte(n)
		n >>= 8
	}
}

type deadlineable interface {
	SetDeadline(time.Time)
}

func (c *Conn) SetDeadline(t time.Time) {
	if d, ok := c.conn.(deadlineable); ok {
		d.SetDeadline(t)
	}
}

func (c *Conn) Read(out []byte) (n int, err error) {
	if len(c.readPending) > 0 {
		n = copy(out, c.readPending)
		c.readPending = c.readPending[n:]
		return
	}

	if c.readBuffer == nil {
		c.readBuffer = make([]byte, blockSize+2)
	}

	if _, err := io.ReadFull(c.conn, c.readBuffer[:2]); err != nil {
		return 0, err
	}
	n = int(c.readBuffer[0]) | int(c.readBuffer[1])<<8
	if n > len(c.readBuffer) {
		return 0, errors.New("transport: peer's message too large for Read")
	}
	if _, err := io.ReadFull(c.conn, c.readBuffer[:n]); err != nil {
		return 0, err
	}

	var ok bool
	if len(out) >= n-secretbox.Overhead {
		// We can decrypt directly into the output buffer.
		out, ok = secretbox.Open(out[:0], c.readBuffer[:n], &c.readSequence, &c.readKey)
		n = len(out)
	} else {
		// We need to decrypt into a side buffer and copy a prefix of
		// the result into the caller's buffer.
		c.decryptBuffer, ok = secretbox.Open(c.decryptBuffer[:0], c.readBuffer[:n], &c.readSequence, &c.readKey)
		n = copy(out, c.decryptBuffer)
		c.readPending = c.decryptBuffer[n:]
	}
	incSequence(&c.readSequence)
	if !ok {
		c.readPending = c.readPending[:0]
		return 0, errors.New("transport: bad MAC")
	}

	return
}

func (c *Conn) Write(buf []byte) (n int, err error) {
	if c.writeBuffer == nil {
		c.writeBuffer = make([]byte, blockSize+2)
	}

	for len(buf) > 0 {
		m := len(buf)
		if m > blockSize-secretbox.Overhead {
			m = blockSize - secretbox.Overhead
		}
		l := len(secretbox.Seal(c.writeBuffer[2:2], buf[:m], &c.writeSequence, &c.writeKey))
		c.writeBuffer[0] = byte(l)
		c.writeBuffer[1] = byte(l >> 8)
		if _, err = c.conn.Write(c.writeBuffer[:2+l]); err != nil {
			return n, err
		}
		n += m
		buf = buf[m:]
		incSequence(&c.writeSequence)
	}

	return
}

func (c *Conn) ReadProto(out proto.Message) error {
	buf := make([]byte, pond.TransportSize+2+secretbox.Overhead)
	n, err := c.read(buf)
	if err != nil {
		return err
	}
	if n != pond.TransportSize+2 {
		return errors.New("transport: message wrong length")
	}

	n = int(buf[0]) | int(buf[1])<<8
	buf = buf[2:]
	if n > len(buf) {
		return errors.New("transport: corrupt message")
	}
	return proto.Unmarshal(buf[:n], out)
}

func (c *Conn) WriteProto(msg proto.Message) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	if len(data) > pond.TransportSize {
		return errors.New("transport: message too large")
	}

	buf := make([]byte, pond.TransportSize+2)
	buf[0] = byte(len(data))
	buf[1] = byte(len(data) >> 8)
	copy(buf[2:], data)
	_, err = c.write(buf)
	return err
}

func (c *Conn) Close() (err error) {
	if !c.isServer {
		_, err = c.write(nil)
	}

	if closeErr := c.conn.Close(); err == nil {
		err = closeErr
	}

	return
}

func (c *Conn) WaitForClose() error {
	if !c.isServer {
		panic("non-server waited for connection close")
	}
	n, err := c.read(make([]byte, 128))
	if err != nil {
		return err
	}
	if n != 0 {
		return errors.New("transport: non-close message received when expecting close")
	}

	return nil
}

func (c *Conn) read(data []byte) (n int, err error) {
	var lengthBytes [2]byte

	if _, err := io.ReadFull(c.conn, lengthBytes[:]); err != nil {
		return 0, err
	}

	theirLength := int(lengthBytes[0]) + int(lengthBytes[1])<<8
	if theirLength > len(data) {
		return 0, errors.New("tranport: given buffer too small (" + strconv.Itoa(len(data)) + " vs " + strconv.Itoa(theirLength) + ")")
	}

	data = data[:theirLength]
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return 0, err
	}

	decrypted, err := c.decrypt(data)
	if err != nil {
		return 0, err
	}
	copy(data, decrypted)

	return len(decrypted), nil
}

func (c *Conn) write(data []byte) (n int, err error) {
	encrypted := c.encrypt(data)

	var lengthBytes [2]byte
	lengthBytes[0] = byte(len(encrypted))
	lengthBytes[1] = byte(len(encrypted) >> 8)

	if _, err := c.conn.Write(lengthBytes[:]); err != nil {
		return 0, err
	}
	if _, err := c.conn.Write(encrypted); err != nil {
		return 0, err
	}

	return len(data), nil
}

func (c *Conn) encrypt(data []byte) []byte {
	if !c.writeKeyValid {
		return data
	}

	encrypted := secretbox.Seal(nil, data, &c.writeSequence, &c.writeKey)
	incSequence(&c.writeSequence)
	return encrypted
}

func (c *Conn) decrypt(data []byte) ([]byte, error) {
	if !c.readKeyValid {
		return data, nil
	}

	decrypted, ok := secretbox.Open(nil, data, &c.readSequence, &c.readKey)
	incSequence(&c.readSequence)
	if !ok {
		return nil, errors.New("transport: bad MAC")
	}
	return decrypted, nil
}

var serverKeysMagic = []byte("server keys\x00")
var clientKeysMagic = []byte("client keys\x00")

func (c *Conn) setupKeys(ephemeralShared *[32]byte) {
	var writeMagic, readMagic []byte
	if c.isServer {
		writeMagic, readMagic = serverKeysMagic, clientKeysMagic
	} else {
		writeMagic, readMagic = clientKeysMagic, serverKeysMagic
	}

	h := sha256.New()
	h.Write(writeMagic)
	h.Write(ephemeralShared[:])
	h.Sum(c.writeKey[:0])
	c.writeKeyValid = true

	h.Reset()
	h.Write(readMagic)
	h.Write(ephemeralShared[:])
	h.Sum(c.readKey[:0])
	c.readKeyValid = true
}

var serverProofMagic = []byte("server proof\x00")
var clientProofMagic = []byte("client proof\x00")

var shortMessageError = errors.New("transport: received short handshake message")

func (c *Conn) Handshake() error {
	var ephemeralPrivate, ephemeralPublic, ephemeralShared [32]byte
	if _, err := io.ReadFull(rand.Reader, ephemeralPrivate[:]); err != nil {
		return err
	}
	curve25519.ScalarBaseMult(&ephemeralPublic, &ephemeralPrivate)

	if _, err := c.write(ephemeralPublic[:]); err != nil {
		return err
	}

	var theirEphemeralPublic [32]byte
	if n, err := c.read(theirEphemeralPublic[:]); err != nil || n != len(theirEphemeralPublic) {
		if err == nil {
			err = shortMessageError
		}
		return err
	}

	handshakeHash := sha256.New()
	if c.isServer {
		handshakeHash.Write(theirEphemeralPublic[:])
		handshakeHash.Write(ephemeralPublic[:])
	} else {
		handshakeHash.Write(ephemeralPublic[:])
		handshakeHash.Write(theirEphemeralPublic[:])
	}

	curve25519.ScalarMult(&ephemeralShared, &ephemeralPrivate, &theirEphemeralPublic)
	c.setupKeys(&ephemeralShared)

	if c.isServer {
		return c.handshakeServer(handshakeHash, &theirEphemeralPublic)
	}
	return c.handshakeClient(handshakeHash, &ephemeralPrivate)
}

func (c *Conn) handshakeClient(handshakeHash hash.Hash, ephemeralPrivate *[32]byte) error {
	var ephemeralIdentityShared [32]byte
	curve25519.ScalarMult(&ephemeralIdentityShared, ephemeralPrivate, &c.Peer)

	digest := handshakeHash.Sum(nil)
	h := hmac.New(sha256.New, ephemeralIdentityShared[:])
	h.Write(serverProofMagic)
	h.Write(digest)
	digest = h.Sum(digest[:0])

	digestReceived := make([]byte, len(digest)+secretbox.Overhead)
	n, err := c.read(digestReceived)
	if err != nil {
		return err
	}
	if n != len(digest) {
		return shortMessageError
	}
	digestReceived = digestReceived[:n]

	if subtle.ConstantTimeCompare(digest, digestReceived) != 1 {
		return errors.New("transport: server identity incorrect")
	}

	var identityShared [32]byte
	curve25519.ScalarMult(&identityShared, &c.identity, &c.Peer)

	handshakeHash.Write(digest)
	digest = handshakeHash.Sum(digest[:0])

	h = hmac.New(sha256.New, identityShared[:])
	h.Write(clientProofMagic)
	h.Write(digest)

	finalMessage := make([]byte, 32+sha256.Size)
	copy(finalMessage, c.identityPublic[:])
	h.Sum(finalMessage[32:32])

	if _, err := c.write(finalMessage); err != nil {
		return err
	}

	return nil
}

func (c *Conn) handshakeServer(handshakeHash hash.Hash, theirEphemeralPublic *[32]byte) error {
	var ephemeralIdentityShared [32]byte
	curve25519.ScalarMult(&ephemeralIdentityShared, &c.identity, theirEphemeralPublic)

	digest := handshakeHash.Sum(nil)
	h := hmac.New(sha256.New, ephemeralIdentityShared[:])
	h.Write(serverProofMagic)
	h.Write(digest)
	digest = h.Sum(digest[:0])

	if _, err := c.write(digest); err != nil {
		return err
	}

	handshakeHash.Write(digest)
	digest = handshakeHash.Sum(digest[:0])

	finalMessage := make([]byte, 32+sha256.Size+secretbox.Overhead)
	n, err := c.read(finalMessage)
	if err != nil {
		return err
	}
	if n != 32+sha256.Size {
		return shortMessageError
	}
	finalMessage = finalMessage[:n]

	copy(c.Peer[:], finalMessage[:32])
	var identityShared [32]byte
	curve25519.ScalarMult(&identityShared, &c.identity, &c.Peer)

	h = hmac.New(sha256.New, identityShared[:])
	h.Write(clientProofMagic)
	h.Write(digest)
	digest = h.Sum(digest[:0])

	if subtle.ConstantTimeCompare(digest, finalMessage[32:]) != 1 {
		return errors.New("transport: bad proof from client")
	}

	return nil
}
