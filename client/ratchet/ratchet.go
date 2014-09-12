// Package ratchet implements the axolotl ratchet, by Trevor Perrin. See
// https://github.com/trevp/axolotl/wiki.
package ratchet

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"time"

	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/pond/client/disk"
	pond "github.com/agl/pond/protos"
)

const (
	// headerSize is the size, in bytes, of a header's plaintext contents.
	headerSize = 4 /* uint32 message count */ +
		4 /* uint32 previous message count */ +
		32 /* curve25519 ratchet public */ +
		24 /* nonce for message */
	// sealedHeader is the size, in bytes, of an encrypted header.
	sealedHeaderSize = 24 /* nonce */ + headerSize + secretbox.Overhead
	// nonceInHeaderOffset is the offset of the message nonce in the
	// header's plaintext.
	nonceInHeaderOffset = 4 + 4 + 32
	// maxMissingMessages is the maximum number of missing messages that
	// we'll allow to be skipped over.
	maxMissingMessages = 100
)

// Ratchet contains the per-contact, crypto state.
type Ratchet struct {
	// MyIdentityPrivate and TheirIdentityPublic contain the primary,
	// curve25519 identity keys. These are pointers because the canonical
	// copies live in the client and Contact structs.
	MyIdentityPrivate, TheirIdentityPublic *[32]byte
	// MySigningPublic and TheirSigningPublic are Ed25519 keys. Again,
	// these are pointers because the canonical versions are kept
	// elsewhere.
	MySigningPublic, TheirSigningPublic *[32]byte
	// Now is an optional function that will be used to get the current
	// time. If nil, time.Now is used.
	Now func() time.Time

	// rootKey gets updated by the DH ratchet.
	rootKey [32]byte
	// Header keys are used to encrypt message headers.
	sendHeaderKey, recvHeaderKey         [32]byte
	nextSendHeaderKey, nextRecvHeaderKey [32]byte
	// Chain keys are used for forward secrecy updating.
	sendChainKey, recvChainKey            [32]byte
	sendRatchetPrivate, recvRatchetPublic [32]byte
	sendCount, recvCount                  uint32
	prevSendCount                         uint32
	// ratchet is true if we will send a new ratchet value in the next message.
	ratchet bool

	// kxPrivate0 and kxPrivate1 contain curve25519 private values during
	// the key exchange phase. They are not valid once key exchange has
	// completed.
	kxPrivate0, kxPrivate1 *[32]byte

	// v2 is true if we are using the updated ratchet with better forward
	// security properties.
	v2 bool

	rand io.Reader
}

func (r *Ratchet) randBytes(buf []byte) {
	if _, err := io.ReadFull(r.rand, buf); err != nil {
		panic(err)
	}
}

func New(rand io.Reader) *Ratchet {
	r := &Ratchet{
		rand:       rand,
		kxPrivate0: new([32]byte),
		kxPrivate1: new([32]byte),
	}

	r.randBytes(r.kxPrivate0[:])
	r.randBytes(r.kxPrivate1[:])

	return r
}

// FillKeyExchange sets elements of kx with key exchange information from the
// ratchet.
func (r *Ratchet) FillKeyExchange(kx *pond.KeyExchange) error {
	if r.kxPrivate0 == nil || r.kxPrivate1 == nil {
		return errors.New("ratchet: handshake already complete")
	}

	var public0, public1 [32]byte
	curve25519.ScalarBaseMult(&public0, r.kxPrivate0)
	curve25519.ScalarBaseMult(&public1, r.kxPrivate1)

	kx.Dh = public0[:]
	kx.Dh1 = public1[:]

	return nil
}

// deriveKey takes an HMAC object and a label and calculates out = HMAC(k, label).
func deriveKey(out *[32]byte, label []byte, h hash.Hash) {
	h.Reset()
	h.Write(label)
	n := h.Sum(out[:0])
	if &n[0] != &out[0] {
		panic("hash function too large")
	}
}

// These constants are used as the label argument to deriveKey to derive
// independent keys from a master key.
var (
	chainKeyLabel          = []byte("chain key")
	headerKeyLabel         = []byte("header key")
	nextRecvHeaderKeyLabel = []byte("next receive header key")
	rootKeyLabel           = []byte("root key")
	rootKeyUpdateLabel     = []byte("root key update")
	sendHeaderKeyLabel     = []byte("next send header key")
	messageKeyLabel        = []byte("message key")
	chainKeyStepLabel      = []byte("chain key step")
)

// GetKXPrivateForTransition returns the DH private key used in the key
// exchange. This exists in order to support the transition to the new ratchet
// format.
func (r *Ratchet) GetKXPrivateForTransition() [32]byte {
	return *r.kxPrivate0
}

// CompleteKeyExchange takes a KeyExchange message from the other party and
// establishes the ratchet.
func (r *Ratchet) CompleteKeyExchange(kx *pond.KeyExchange, isV2 bool) error {
	if r.kxPrivate0 == nil {
		return errors.New("ratchet: handshake already complete")
	}

	var public0 [32]byte
	curve25519.ScalarBaseMult(&public0, r.kxPrivate0)

	if len(kx.Dh) != len(public0) {
		return errors.New("ratchet: peer's key exchange is invalid")
	}
	if len(kx.Dh1) != len(public0) {
		return errors.New("ratchet: peer using old-form key exchange")
	}

	var amAlice bool
	switch bytes.Compare(public0[:], kx.Dh) {
	case -1:
		amAlice = true
	case 1:
		amAlice = false
	case 0:
		return errors.New("ratchet: peer echoed our own DH values back")
	}

	var theirDH [32]byte
	copy(theirDH[:], kx.Dh)

	keyMaterial := make([]byte, 0, 32*5)
	var sharedKey [32]byte
	curve25519.ScalarMult(&sharedKey, r.kxPrivate0, &theirDH)
	keyMaterial = append(keyMaterial, sharedKey[:]...)

	if amAlice {
		curve25519.ScalarMult(&sharedKey, r.MyIdentityPrivate, &theirDH)
		keyMaterial = append(keyMaterial, sharedKey[:]...)
		curve25519.ScalarMult(&sharedKey, r.kxPrivate0, r.TheirIdentityPublic)
		keyMaterial = append(keyMaterial, sharedKey[:]...)
		if !isV2 {
			keyMaterial = append(keyMaterial, r.MySigningPublic[:]...)
			keyMaterial = append(keyMaterial, r.TheirSigningPublic[:]...)
		}
	} else {
		curve25519.ScalarMult(&sharedKey, r.kxPrivate0, r.TheirIdentityPublic)
		keyMaterial = append(keyMaterial, sharedKey[:]...)
		curve25519.ScalarMult(&sharedKey, r.MyIdentityPrivate, &theirDH)
		keyMaterial = append(keyMaterial, sharedKey[:]...)
		if !isV2 {
			keyMaterial = append(keyMaterial, r.TheirSigningPublic[:]...)
			keyMaterial = append(keyMaterial, r.MySigningPublic[:]...)
		}
	}

	h := hmac.New(sha256.New, keyMaterial)
	deriveKey(&r.rootKey, rootKeyLabel, h)
	if amAlice {
		deriveKey(&r.recvHeaderKey, headerKeyLabel, h)
		deriveKey(&r.nextSendHeaderKey, sendHeaderKeyLabel, h)
		deriveKey(&r.nextRecvHeaderKey, nextRecvHeaderKeyLabel, h)
		deriveKey(&r.recvChainKey, chainKeyLabel, h)
		copy(r.recvRatchetPublic[:], kx.Dh1)
	} else {
		deriveKey(&r.sendHeaderKey, headerKeyLabel, h)
		deriveKey(&r.nextRecvHeaderKey, sendHeaderKeyLabel, h)
		deriveKey(&r.nextSendHeaderKey, nextRecvHeaderKeyLabel, h)
		deriveKey(&r.sendChainKey, chainKeyLabel, h)
		copy(r.sendRatchetPrivate[:], r.kxPrivate1[:])
	}

	r.ratchet = amAlice
	r.kxPrivate0 = nil
	r.kxPrivate1 = nil
	r.v2 = isV2

	return nil
}

// Encrypt acts like append() but appends an encrypted version of msg to out.
func (r *Ratchet) Encrypt(out, msg []byte) []byte {
	if r.ratchet {
		r.randBytes(r.sendRatchetPrivate[:])
		copy(r.sendHeaderKey[:], r.nextSendHeaderKey[:])

		var sharedKey, keyMaterial [32]byte
		curve25519.ScalarMult(&sharedKey, &r.sendRatchetPrivate, &r.recvRatchetPublic)
		sha := sha256.New()
		sha.Write(rootKeyUpdateLabel)
		sha.Write(r.rootKey[:])
		sha.Write(sharedKey[:])

		if r.v2 {
			sha.Sum(keyMaterial[:0])
			h := hmac.New(sha256.New, keyMaterial[:])
			deriveKey(&r.rootKey, rootKeyLabel, h)
			deriveKey(&r.nextSendHeaderKey, sendHeaderKeyLabel, h)
			deriveKey(&r.sendChainKey, chainKeyLabel, h)
		} else {
			sha.Sum(r.rootKey[:0])
			h := hmac.New(sha256.New, r.rootKey[:])
			deriveKey(&r.nextSendHeaderKey, sendHeaderKeyLabel, h)
			deriveKey(&r.sendChainKey, chainKeyLabel, h)
		}
		r.prevSendCount, r.sendCount = r.sendCount, 0
		r.ratchet = false
	}

	h := hmac.New(sha256.New, r.sendChainKey[:])
	var messageKey [32]byte
	deriveKey(&messageKey, messageKeyLabel, h)
	deriveKey(&r.sendChainKey, chainKeyStepLabel, h)

	var sendRatchetPublic [32]byte
	curve25519.ScalarBaseMult(&sendRatchetPublic, &r.sendRatchetPrivate)
	var header [headerSize]byte
	var headerNonce, messageNonce [24]byte
	r.randBytes(headerNonce[:])
	r.randBytes(messageNonce[:])

	binary.LittleEndian.PutUint32(header[0:4], r.sendCount)
	binary.LittleEndian.PutUint32(header[4:8], r.prevSendCount)
	copy(header[8:], sendRatchetPublic[:])
	copy(header[nonceInHeaderOffset:], messageNonce[:])
	out = append(out, headerNonce[:]...)
	out = secretbox.Seal(out, header[:], &headerNonce, &r.sendHeaderKey)
	r.sendCount++
	return secretbox.Seal(out, msg, &messageNonce, &messageKey)
}

// calculateKeys takes a header key, the current chain key, a received message
// number and the expected message number and advances the chain key as needed.
// It returns the message key for given given message number and the new chain
// key. It also returns the number of missing messages.
func (r *Ratchet) calculateKeys(headerKey, recvChainKey *[32]byte, messageNum, receivedCount uint32) (provisionalChainKey, messageKey [32]byte, numMissing uint32, err error) {
	if messageNum < receivedCount {
		// This is a message from the past which means that it's a
		// duplicate message or that we thought that it had been
		// dropped.
		err = errors.New("ratchet: duplicate message or past message cannot be decrypted")
		return
	}

	numMissing = messageNum - receivedCount
	if numMissing > maxMissingMessages {
		err = errors.New("ratchet: message exceeds reordering limit")
		return
	}

	copy(provisionalChainKey[:], recvChainKey[:])

	for n := receivedCount; n <= messageNum; n++ {
		h := hmac.New(sha256.New, provisionalChainKey[:])
		deriveKey(&messageKey, messageKeyLabel, h)
		deriveKey(&provisionalChainKey, chainKeyStepLabel, h)
	}

	return
}

// isZeroKey returns true if key is all zeros.
func isZeroKey(key *[32]byte) bool {
	var x uint8
	for _, v := range key {
		x |= v
	}

	return x == 0
}

// Decrypt decrypts a message and returns the plaintext and number of messages
// that were missed, or an error.
func (r *Ratchet) Decrypt(ciphertext []byte) ([]byte, int, error) {
	if len(ciphertext) < sealedHeaderSize {
		return nil, 0, errors.New("ratchet: ciphertext too small")
	}
	sealedHeader := ciphertext[:sealedHeaderSize]
	sealedMessage := ciphertext[sealedHeaderSize:]
	var nonce [24]byte
	copy(nonce[:], sealedHeader)
	sealedHeader = sealedHeader[len(nonce):]

	header, ok := secretbox.Open(nil, sealedHeader, &nonce, &r.recvHeaderKey)
	ok = ok && !isZeroKey(&r.recvHeaderKey)
	if ok {
		if len(header) != headerSize {
			return nil, 0, errors.New("ratchet: incorrect header size")
		}
		messageNum := binary.LittleEndian.Uint32(header[:4])
		provisionalChainKey, messageKey, numMissingMessages, err := r.calculateKeys(&r.recvHeaderKey, &r.recvChainKey, messageNum, r.recvCount)
		if err != nil {
			return nil, 0, err
		}

		copy(nonce[:], header[nonceInHeaderOffset:])
		msg, ok := secretbox.Open(nil, sealedMessage, &nonce, &messageKey)
		if !ok {
			return nil, 0, errors.New("ratchet: corrupt message")
		}

		copy(r.recvChainKey[:], provisionalChainKey[:])
		r.recvCount = messageNum + 1
		return msg, int(numMissingMessages), nil
	}

	header, ok = secretbox.Open(nil, sealedHeader, &nonce, &r.nextRecvHeaderKey)
	if !ok {
		return nil, 0, errors.New("ratchet: cannot decrypt")
	}
	if len(header) != headerSize {
		return nil, 0, errors.New("ratchet: incorrect header size")
	}

	if r.ratchet {
		return nil, 0, errors.New("ratchet: received message encrypted to next header key without ratchet flag set")
	}

	messageNum := binary.LittleEndian.Uint32(header[:4])
	prevMessageCount := binary.LittleEndian.Uint32(header[4:8])

	_, _, numMissingMessages, err := r.calculateKeys(&r.recvHeaderKey, &r.recvChainKey, prevMessageCount, r.recvCount)
	if err != nil {
		return nil, 0, err
	}

	var dhPublic, sharedKey, rootKey, chainKey, keyMaterial [32]byte
	copy(dhPublic[:], header[8:])

	curve25519.ScalarMult(&sharedKey, &r.sendRatchetPrivate, &dhPublic)

	sha := sha256.New()
	sha.Write(rootKeyUpdateLabel)
	sha.Write(r.rootKey[:])
	sha.Write(sharedKey[:])

	var rootKeyHMAC hash.Hash

	if r.v2 {
		sha.Sum(keyMaterial[:0])
		rootKeyHMAC = hmac.New(sha256.New, keyMaterial[:])
		deriveKey(&rootKey, rootKeyLabel, rootKeyHMAC)
	} else {
		sha.Sum(rootKey[:0])
		rootKeyHMAC = hmac.New(sha256.New, rootKey[:])
	}
	deriveKey(&chainKey, chainKeyLabel, rootKeyHMAC)

	provisionalChainKey, messageKey, numMissingMessages2, err := r.calculateKeys(&r.nextRecvHeaderKey, &chainKey, messageNum, 0)
	if err != nil {
		return nil, 0, err
	}

	copy(nonce[:], header[nonceInHeaderOffset:])
	msg, ok := secretbox.Open(nil, sealedMessage, &nonce, &messageKey)
	if !ok {
		return nil, 0, errors.New("ratchet: corrupt message")
	}

	copy(r.rootKey[:], rootKey[:])
	copy(r.recvChainKey[:], provisionalChainKey[:])
	copy(r.recvHeaderKey[:], r.nextRecvHeaderKey[:])
	deriveKey(&r.nextRecvHeaderKey, sendHeaderKeyLabel, rootKeyHMAC)
	for i := range r.sendRatchetPrivate {
		r.sendRatchetPrivate[i] = 0
	}
	copy(r.recvRatchetPublic[:], dhPublic[:])

	r.recvCount = messageNum + 1
	r.ratchet = true

	return msg, int(numMissingMessages + numMissingMessages2), nil
}

func dup(key *[32]byte) []byte {
	if key == nil {
		return nil
	}

	ret := make([]byte, 32)
	copy(ret, key[:])
	return ret
}

func (r *Ratchet) Marshal(now time.Time, lifetime time.Duration) *disk.RatchetState {
	s := &disk.RatchetState{
		RootKey:            dup(&r.rootKey),
		SendHeaderKey:      dup(&r.sendHeaderKey),
		RecvHeaderKey:      dup(&r.recvHeaderKey),
		NextSendHeaderKey:  dup(&r.nextSendHeaderKey),
		NextRecvHeaderKey:  dup(&r.nextRecvHeaderKey),
		SendChainKey:       dup(&r.sendChainKey),
		RecvChainKey:       dup(&r.recvChainKey),
		SendRatchetPrivate: dup(&r.sendRatchetPrivate),
		RecvRatchetPublic:  dup(&r.recvRatchetPublic),
		SendCount:          proto.Uint32(r.sendCount),
		RecvCount:          proto.Uint32(r.recvCount),
		PrevSendCount:      proto.Uint32(r.prevSendCount),
		Ratchet:            proto.Bool(r.ratchet),
		Private0:           dup(r.kxPrivate0),
		Private1:           dup(r.kxPrivate1),
		V2:                 proto.Bool(r.v2),
	}

	return s
}

func unmarshalKey(dst *[32]byte, src []byte) bool {
	if len(src) != 32 {
		return false
	}
	copy(dst[:], src)
	return true
}

var badSerialisedKeyLengthErr = errors.New("ratchet: bad serialised key length")

func (r *Ratchet) Unmarshal(s *disk.RatchetState) error {
	if !unmarshalKey(&r.rootKey, s.RootKey) ||
		!unmarshalKey(&r.sendHeaderKey, s.SendHeaderKey) ||
		!unmarshalKey(&r.recvHeaderKey, s.RecvHeaderKey) ||
		!unmarshalKey(&r.nextSendHeaderKey, s.NextSendHeaderKey) ||
		!unmarshalKey(&r.nextRecvHeaderKey, s.NextRecvHeaderKey) ||
		!unmarshalKey(&r.sendChainKey, s.SendChainKey) ||
		!unmarshalKey(&r.recvChainKey, s.RecvChainKey) ||
		!unmarshalKey(&r.sendRatchetPrivate, s.SendRatchetPrivate) ||
		!unmarshalKey(&r.recvRatchetPublic, s.RecvRatchetPublic) {
		return badSerialisedKeyLengthErr
	}

	r.sendCount = *s.SendCount
	r.recvCount = *s.RecvCount
	r.prevSendCount = *s.PrevSendCount
	r.ratchet = *s.Ratchet
	r.v2 = s.GetV2()

	if len(s.Private0) > 0 {
		if !unmarshalKey(r.kxPrivate0, s.Private0) ||
			!unmarshalKey(r.kxPrivate1, s.Private1) {
			return badSerialisedKeyLengthErr
		}
	} else {
		r.kxPrivate0 = nil
		r.kxPrivate1 = nil
	}

	return nil
}
