package panda

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/go.crypto/scrypt"
	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/pond/panda/rijndael"

	panda_proto "github.com/agl/pond/panda/proto"
)

var ShutdownErr = errors.New("panda: shutdown requested")

type SharedSecret struct {
	Secret           string
	Cards            CardStack
	Day, Month, Year int
	Hours, Minutes   int
}

func (s *SharedSecret) toProto() *panda_proto.KeyExchange_SharedSecret {
	ret := new(panda_proto.KeyExchange_SharedSecret)
	if len(s.Secret) > 0 {
		ret.Secret = proto.String(s.Secret)
	}
	if s.Cards.NumDecks > 0 {
		ret.NumDecks = proto.Int32(int32(s.Cards.NumDecks))
		canonical := s.Cards.Canonicalise()
		ret.CardCount = canonical.counts[:]
	}
	if s.Year != 0 {
		ret.Time = &panda_proto.KeyExchange_SharedSecret_Time{
			Day:     proto.Int32(int32(s.Day)),
			Month:   proto.Int32(int32(s.Month)),
			Year:    proto.Int32(int32(s.Year)),
			Hours:   proto.Int32(int32(s.Hours)),
			Minutes: proto.Int32(int32(s.Minutes)),
		}
	}

	return ret
}

func newSharedSecret(p *panda_proto.KeyExchange_SharedSecret) (*SharedSecret, bool) {
	ret := &SharedSecret{
		Secret:  p.GetSecret(),
		Day:     int(p.Time.GetDay()),
		Month:   int(p.Time.GetMonth()),
		Year:    int(p.Time.GetYear()),
		Hours:   int(p.Time.GetHours()),
		Minutes: int(p.Time.GetMinutes()),
	}
	ret.Cards.NumDecks = int(p.GetNumDecks())
	if ret.Cards.NumDecks > 0 {
		if len(p.CardCount) != numCards {
			return nil, false
		}
		copy(ret.Cards.counts[:], p.CardCount)
	} else {
		if len(ret.Secret) == 0 {
			return nil, false
		}
	}

	return ret, true
}

type MeetingPlace interface {
	Padding() int
	Exchange(log func(string, ...interface{}), id, message []byte) ([]byte, error)
}

type KeyExchange struct {
	sync.Mutex

	Log          func(string, ...interface{})
	Testing      bool
	ShutdownChan chan bool

	rand         io.Reader
	status       panda_proto.KeyExchange_Status
	meetingPlace MeetingPlace
	sharedSecret *SharedSecret
	serialised   []byte
	kxBytes      []byte

	key, meeting1, meeting2 [32]byte
	dhPublic, dhPrivate     [32]byte
	sharedKey               [32]byte
	message1, message2      []byte
}

func NewKeyExchange(rand io.Reader, meetingPlace MeetingPlace, sharedSecret *SharedSecret, kxBytes []byte) (*KeyExchange, error) {
	if 24 /* nonce */ +4 /* length */ +len(kxBytes)+secretbox.Overhead > meetingPlace.Padding() {
		return nil, errors.New("panda: key exchange too large for meeting place")
	}

	kx := &KeyExchange{
		Log:          func(format string, args ...interface{}) {},
		rand:         rand,
		meetingPlace: meetingPlace,
		status:       panda_proto.KeyExchange_INIT,
		sharedSecret: sharedSecret,
		kxBytes:      kxBytes,
	}

	if _, err := io.ReadFull(kx.rand, kx.dhPrivate[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&kx.dhPublic, &kx.dhPrivate)
	kx.updateSerialised()

	return kx, nil
}

func UnmarshalKeyExchange(rand io.Reader, meetingPlace MeetingPlace, serialised []byte) (*KeyExchange, error) {
	var p panda_proto.KeyExchange
	if err := proto.Unmarshal(serialised, &p); err != nil {
		return nil, err
	}

	sharedSecret, ok := newSharedSecret(p.SharedSecret)
	if !ok {
		return nil, errors.New("panda: invalid shared secret in serialised key exchange")
	}

	kx := &KeyExchange{
		rand:         rand,
		meetingPlace: meetingPlace,
		status:       p.GetStatus(),
		sharedSecret: sharedSecret,
		serialised:   serialised,
		kxBytes:      p.KeyExchangeBytes,
		message1:     p.Message1,
		message2:     p.Message2,
	}

	copy(kx.key[:], p.Key)
	copy(kx.meeting1[:], p.Meeting1)
	copy(kx.meeting2[:], p.Meeting2)
	copy(kx.sharedKey[:], p.SharedKey)
	copy(kx.dhPrivate[:], p.DhPrivate)
	curve25519.ScalarBaseMult(&kx.dhPublic, &kx.dhPrivate)

	return kx, nil
}

func (kx *KeyExchange) Marshal() []byte {
	kx.Lock()
	defer kx.Unlock()

	return kx.serialised
}

func (kx *KeyExchange) updateSerialised() {
	p := &panda_proto.KeyExchange{
		Status:           kx.status.Enum(),
		SharedSecret:     kx.sharedSecret.toProto(),
		KeyExchangeBytes: kx.kxBytes,
	}
	if kx.status != panda_proto.KeyExchange_INIT {
		p.DhPrivate = kx.dhPrivate[:]
		p.Key = kx.key[:]
		p.Meeting1 = kx.meeting1[:]
		p.Meeting2 = kx.meeting2[:]
		p.Message1 = kx.message1
		p.Message2 = kx.message2
		p.SharedKey = kx.sharedKey[:]
	}
	serialised, err := proto.Marshal(p)
	if err != nil {
		panic(err)
	}

	kx.Lock()
	defer kx.Unlock()

	kx.serialised = serialised
}

func (kx *KeyExchange) shouldStop() bool {
	select {
	case <-kx.ShutdownChan:
		return true
	default:
		return false
	}

	panic("unreachable")
}

func (kx *KeyExchange) Run() ([]byte, error) {
	switch kx.status {
	case panda_proto.KeyExchange_INIT:
		if err := kx.derivePassword(); err != nil {
			return nil, err
		}
		kx.status = panda_proto.KeyExchange_EXCHANGE1
		kx.updateSerialised()
		kx.Log("password derivation complete.")
		if kx.shouldStop() {
			return nil, ShutdownErr
		}
		fallthrough
	case panda_proto.KeyExchange_EXCHANGE1:
		if err := kx.exchange1(); err != nil {
			return nil, err
		}
		kx.status = panda_proto.KeyExchange_EXCHANGE2
		kx.updateSerialised()
		kx.Log("first message exchange complete")
		if kx.shouldStop() {
			return nil, ShutdownErr
		}
		fallthrough
	case panda_proto.KeyExchange_EXCHANGE2:
		reply, err := kx.exchange2()
		if err != nil {
			return nil, err
		}
		return reply, nil
	default:
		panic("unknown state")
	}

	panic("unreachable")
}

func (kx *KeyExchange) derivePassword() error {
	serialised, err := proto.Marshal(kx.sharedSecret.toProto())
	if err != nil {
		return err
	}

	if kx.Testing {
		h := sha256.New()
		h.Write([]byte{0})
		h.Write(serialised)
		h.Sum(kx.key[:0])

		h.Reset()
		h.Write([]byte{1})
		h.Write(serialised)
		h.Sum(kx.meeting1[:0])

		h.Reset()
		h.Write([]byte{2})
		h.Write(serialised)
		h.Sum(kx.meeting2[:0])
	} else {
		data, err := scrypt.Key(serialised, nil, 1<<16, 16, 4, 32*3)
		if err != nil {
			return err
		}

		copy(kx.key[:], data)
		copy(kx.meeting1[:], data[32:])
		copy(kx.meeting2[:], data[64:])
	}

	var encryptedDHPublic [32]byte
	rijndael.NewCipher(&kx.key).Encrypt(&encryptedDHPublic, &kx.dhPublic)

	l := len(encryptedDHPublic)
	if padding := kx.meetingPlace.Padding(); l > padding {
		return errors.New("panda: initial message too large for meeting place")
	} else if l < padding {
		l = padding
	}

	kx.message1 = make([]byte, l)
	copy(kx.message1, encryptedDHPublic[:])
	if _, err := io.ReadFull(kx.rand, kx.message1[len(encryptedDHPublic):]); err != nil {
		return err
	}

	return nil
}

func (kx *KeyExchange) exchange1() error {
	reply, err := kx.meetingPlace.Exchange(kx.Log, kx.meeting1[:], kx.message1[:])
	if err != nil {
		return err
	}

	var peerDHPublic, encryptedPeerDHPublic [32]byte
	if len(reply) < len(encryptedPeerDHPublic) {
		return errors.New("panda: meeting point reply too small")
	}

	copy(encryptedPeerDHPublic[:], reply)
	rijndael.NewCipher(&kx.key).Decrypt(&peerDHPublic, &encryptedPeerDHPublic)

	curve25519.ScalarMult(&kx.sharedKey, &kx.dhPrivate, &peerDHPublic)

	paddedLen := kx.meetingPlace.Padding()
	padded := make([]byte, paddedLen-24 /* nonce */ -secretbox.Overhead)
	binary.LittleEndian.PutUint32(padded, uint32(len(kx.kxBytes)))
	copy(padded[4:], kx.kxBytes)
	if _, err := io.ReadFull(kx.rand, padded[4+len(kx.kxBytes):]); err != nil {
		return err
	}

	var nonce [24]byte
	if _, err := io.ReadFull(kx.rand, nonce[:]); err != nil {
		return err
	}

	kx.message2 = make([]byte, paddedLen)
	copy(kx.message2, nonce[:])
	secretbox.Seal(kx.message2[24:24], padded, &nonce, &kx.sharedKey)

	return nil
}

func (kx *KeyExchange) exchange2() ([]byte, error) {
	reply, err := kx.meetingPlace.Exchange(kx.Log, kx.meeting2[:], kx.message2[:])
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	if len(reply) < len(nonce) {
		return nil, errors.New("panda: meeting point reply too small")
	}

	if kx.sharedKey[0] == 0 && kx.sharedKey[1] == 0 {
		panic("here")
	}
	copy(nonce[:], reply)
	message, ok := secretbox.Open(nil, reply[24:], &nonce, &kx.sharedKey)
	if !ok {
		return nil, errors.New("panda: peer's message cannot be authenticated")
	}

	if len(message) < 4 {
		return nil, errors.New("panda: peer's message is invalid")
	}
	l := binary.LittleEndian.Uint32(message)
	message = message[4:]
	if l > uint32(len(message)) {
		return nil, errors.New("panda: peer's message is truncated")
	}
	message = message[:int(l)]
	return message, nil
}
