package disk

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"syscall"

	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/go.crypto/scrypt"
	"code.google.com/p/goprotobuf/proto"
)

const (
	kdfSaltLen    = 32
	kdfKeyLen     = 32
	erasureKeyLen = 32
)

var headerMagic = [8]byte{0xa8, 0x34, 0x64, 0x9e, 0xce, 0x39, 0x94, 0xe3}

// ErasureStorage represents a type of storage that can store, and erase, small
// amounts of data.
type ErasureStorage interface {
	// Create creates a new erasure storage object and fills out header to
	// include the needed values.
	Create(header *Header, key *[kdfKeyLen]byte) error
	// Read reads the current value of the storage.
	Read(key *[kdfKeyLen]byte) (*[erasureKeyLen]byte, error)
	// Write requests that the given value be stored and the old value
	// forgotten.
	Write(key *[kdfKeyLen]byte, value *[erasureKeyLen]byte) error
}

// erasureRegistry is a slice of functions, each of which can inspect a header
// and optionally return an ErasureStorage that loads the mask key specified by
// that header.
var erasureRegistry []func(*Header) ErasureStorage

// StateFile encapsulates information about a state file on diskl
type StateFile struct {
	Path    string
	Rand    io.Reader
	// Erasure is able to store a `mask key' - a random value that is XORed
	// with the key. This is done because an ErasureStorage is believed to
	// be able to erase old mask values.
	Erasure ErasureStorage

	header Header
	key    [kdfKeyLen]byte
	mask   [erasureKeyLen]byte
	valid  bool
}

func NewStateFile(rand io.Reader, path string) *StateFile {
	return &StateFile{
		Rand: rand,
		Path: path,
	}
}

func (sf *StateFile) deriveKey(pw string) error {
	params := sf.header.Scrypt
	key, err := scrypt.Key([]byte(pw), sf.header.KdfSalt, int(params.GetN()), int(params.GetR()), int(params.GetP()), kdfKeyLen)
	if err != nil {
		return err
	}
	copy(sf.key[:], key)
	return nil
}

func (sf *StateFile) Create(pw string) error {
	var salt [kdfSaltLen]byte
	if _, err := io.ReadFull(sf.Rand, salt[:]); err != nil {
		return err
	}

	sf.header.KdfSalt = salt[:]
	if err := sf.deriveKey(pw); err != nil {
		return err
	}

	if sf.Erasure != nil {
		if err := sf.Erasure.Create(&sf.header, &sf.key); err != nil {
			return err
		}
		if _, err := io.ReadFull(sf.Rand, sf.mask[:]); err != nil {
			return err
		}
		if err := sf.Erasure.Write(&sf.key, &sf.mask); err != nil {
			return err
		}
	} else {
		sf.header.NoErasureStorage = proto.Bool(true)
	}

	sf.valid = true
	return nil
}

func (sf *StateFile) Read(pw string) (*State, error) {
	b, err := ioutil.ReadFile(sf.Path)
	if err != nil {
		return nil, err
	}

	if len(b) < len(headerMagic)+4 {
		return nil, errors.New("state file is too small to be valid")
	}

	if !bytes.Equal(b[:len(headerMagic)], headerMagic[:]) {
		return sf.ReadOldStyle(b)
	}

	b = b[len(headerMagic):]
	headerLen := binary.LittleEndian.Uint32(b)
	b = b[4:]
	if headerLen > 1<<16 {
		return nil, errors.New("state file corrupt")
	}
	if len(b) < int(headerLen) {
		return nil, errors.New("state file truncated")
	}
	headerBytes := b[:int(headerLen)]
	b = b[int(headerLen):]

	if err := proto.Unmarshal(headerBytes, &sf.header); err != nil {
		return nil, err
	}
	if err := sf.deriveKey(pw); err != nil {
		return nil, err
	}

	if !sf.header.GetNoErasureStorage() {
		for _, erasureMethod := range erasureRegistry {
			sf.Erasure = erasureMethod(&sf.header)
			if sf.Erasure != nil {
				break
			}
		}
		if sf.Erasure == nil {
			return nil, errors.New("unknown erasure storage method")
		}

		mask, err := sf.Erasure.Read(&sf.key)
		if err != nil {
			return nil, err
		}
		copy(sf.mask[:], mask[:])
	}

	smearedCopies := int(sf.header.GetNonceSmearCopies())

	if len(b) < 24*smearedCopies {
		return nil, errors.New("state file truncated")
	}

	var nonce [24]byte
	for i := 0; i < smearedCopies; i++ {
		for j := 0; j < 24; j++ {
			nonce[j] ^= b[24*i+j]
		}
	}

	b = b[24*smearedCopies:]

	var effectiveKey [kdfKeyLen]byte
	for i := range effectiveKey {
		effectiveKey[i] = sf.mask[i] ^ sf.key[i]
	}
	plaintext, ok := secretbox.Open(nil, b, &nonce, &effectiveKey)
	if !ok {
		return nil, BadPasswordError
	}
	if len(plaintext) < 4 {
		return nil, errors.New("state file corrupt")
	}
	length := binary.LittleEndian.Uint32(plaintext[:4])
	plaintext = plaintext[4:]
	if length > 1<<31 || length > uint32(len(plaintext)) {
		return nil, errors.New("state file corrupt")
	}
	plaintext = plaintext[:int(length)]

	var state State
	if err := proto.Unmarshal(plaintext, &state); err != nil {
		return nil, err
	}

	return &state, nil
}

func (sf *StateFile) ReadOldStyle(b []byte) (*State, error) {
	return LoadState(b, &sf.key)
}

func (sf *StateFile) StartWriter(states chan []byte, done chan struct{}) {
	for {
		s, ok := <-states
		if !ok {
			close(done)
			return
		}

		length := uint32(len(s)) + 4
		for i := uint(17); i < 32; i++ {
			if n := (uint32(1) << i); n >= length {
				length = n
				break
			}
		}

		plaintext := make([]byte, length)
		copy(plaintext[4:], s)
		if _, err := io.ReadFull(sf.Rand, plaintext[len(s)+4:]); err != nil {
			panic(err)
		}
		binary.LittleEndian.PutUint32(plaintext, uint32(len(s)))

		smearCopies := int(sf.header.GetNonceSmearCopies())
		nonceSmear := make([]byte, 24*smearCopies)
		if _, err := io.ReadFull(sf.Rand, nonceSmear[:]); err != nil {
			panic(err)
		}

		var nonce [24]byte
		for i := 0; i < smearCopies; i++ {
			for j := 0; j < 24; j++ {
				nonce[j] ^= nonceSmear[24*i+j]
			}
		}

		var effectiveKey [kdfKeyLen]byte
		for i := range effectiveKey {
			effectiveKey[i] = sf.mask[i] ^ sf.key[i]
		}
		ciphertext := secretbox.Seal(nil, plaintext, &nonce, effectiveKey)

		out, err := os.OpenFile(sf.Path, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			panic(err)
		}
		headerBytes, err := proto.Marshal(&sf.header)
		if err != nil {
			panic(err)
		}
		if _, err := out.Write(headerMagic[:]); err != nil {
			panic(err)
		}
		if err := binary.Write(out, binary.LittleEndian, uint32(len(headerBytes))); err != nil {
			panic(err)
		}
		if _, err := out.Write(headerBytes); err != nil {
			panic(err)
		}
		if _, err := out.Write(nonceSmear[:]); err != nil {
			panic(err)
		}
		if _, err := out.Write(ciphertext); err != nil {
			panic(err)
		}
		out.Close()
	}
}

func DeriveKey(pw string, diskSalt *[32]byte) ([]byte, error) {
	return scrypt.Key([]byte(pw), diskSalt[:], 32768, 16, 1, 32)
}

const SCryptSaltLen = 32
const smearedCopies = 32768 / 24

func GetSCryptSaltFromState(state []byte) ([32]byte, bool) {
	var salt [32]byte
	if len(state) < SCryptSaltLen {
		return salt, false
	}
	copy(salt[:], state)
	return salt, true
}

type Lock struct {
	fd int
}

func (l *Lock) Close() {
	syscall.Flock(l.fd, syscall.LOCK_UN)
	syscall.Close(l.fd)
}

// LockStateFile attempts to lock the given file. If successful, it returns
// true and the lock persists for the lifetime of the process.
func LockStateFile(stateFile *os.File) (*Lock, bool) {
	fd := int(stateFile.Fd())
	newFd, err := syscall.Dup(fd)
	if err != nil {
		panic(err)
	}
	if syscall.Flock(newFd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		syscall.Close(newFd)
		return nil, false
	}
	return &Lock{newFd}, true
}

func StateWriter(stateFilename string, key *[32]byte, salt *[SCryptSaltLen]byte, states chan []byte, done chan struct{}) {
	for {
		s, ok := <-states
		if !ok {
			close(done)
			return
		}

		length := uint32(len(s)) + 4
		for i := uint(17); i < 32; i++ {
			if n := (uint32(1) << i); n >= length {
				length = n
				break
			}
		}

		plaintext := make([]byte, length)
		copy(plaintext[4:], s)
		if _, err := io.ReadFull(rand.Reader, plaintext[len(s)+4:]); err != nil {
			panic(err)
		}
		binary.LittleEndian.PutUint32(plaintext, uint32(len(s)))

		var nonceSmear [24 * smearedCopies]byte
		if _, err := io.ReadFull(rand.Reader, nonceSmear[:]); err != nil {
			panic(err)
		}

		var nonce [24]byte
		for i := 0; i < smearedCopies; i++ {
			for j := 0; j < 24; j++ {
				nonce[j] ^= nonceSmear[24*i+j]
			}
		}

		ciphertext := secretbox.Seal(nil, plaintext, &nonce, key)

		out, err := os.OpenFile(stateFilename, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			panic(err)
		}
		if _, err := out.Write(salt[:]); err != nil {
			panic(err)
		}
		if _, err := out.Write(nonceSmear[:]); err != nil {
			panic(err)
		}
		if _, err := out.Write(ciphertext); err != nil {
			panic(err)
		}
		out.Close()
	}
}

var BadPasswordError = errors.New("bad password")

func LoadState(b []byte, key *[32]byte) (*State, error) {
	if len(b) < SCryptSaltLen+24*smearedCopies {
		return nil, errors.New("state file is too small to be valid")
	}

	b = b[SCryptSaltLen:]

	var nonce [24]byte
	for i := 0; i < smearedCopies; i++ {
		for j := 0; j < 24; j++ {
			nonce[j] ^= b[24*i+j]
		}
	}

	b = b[24*smearedCopies:]
	plaintext, ok := secretbox.Open(nil, b, &nonce, key)
	if !ok {
		return nil, BadPasswordError
	}
	if len(plaintext) < 4 {
		return nil, errors.New("state file corrupt")
	}
	length := binary.LittleEndian.Uint32(plaintext[:4])
	plaintext = plaintext[4:]
	if length > 1<<31 || length > uint32(len(plaintext)) {
		return nil, errors.New("state file corrupt")
	}
	plaintext = plaintext[:int(length)]

	var state State
	if err := proto.Unmarshal(plaintext, &state); err != nil {
		return nil, err
	}

	return &state, nil
}
