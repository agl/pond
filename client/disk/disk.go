package disk

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"

	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/go.crypto/scrypt"
	"code.google.com/p/goprotobuf/proto"
)

func DeriveKey(pw string, diskSalt *[32]byte) ([]byte, error) {
	return scrypt.Key([]byte(pw), diskSalt[:], 32768, 16, 1, 32)
}

const SCryptSaltLen = 32
const diskSaltLen = 32
const smearedCopies = 32768 / 24

func GetSCryptSaltFromState(state []byte) ([32]byte, bool) {
	var salt [32]byte
	if len(state) < SCryptSaltLen {
		return salt, false
	}
	copy(salt[:], state)
	return salt, true
}

func StateWriter(stateFilename string, key *[32]byte, salt *[SCryptSaltLen]byte, states chan []byte, done chan bool) {
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

		out, err := os.Create(stateFilename)
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
