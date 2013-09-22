// decrypt is a tiny utility that can decrypt Pond detachments given the key
// file. The key file can be saved to disk from within the main Pond client.
// Later the bulk of the data, transported by other means, can be decrypted
// with this utility. (Or the main Pond client itself.)
package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"code.google.com/p/go.crypto/nacl/secretbox"
	"code.google.com/p/goprotobuf/proto"
	pond "github.com/agl/pond/protos"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <key file> < encrypted > decrypted\n", os.Args[0])
		os.Exit(1)
	}

	if err := do(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func do(keyFile string) error {
	contents, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		return err
	}

	var detachment pond.Message_Detachment
	if err := proto.Unmarshal(contents, &detachment); err != nil {
		return err
	}

	size := detachment.GetSize()
	paddedSize := detachment.GetPaddedSize()
	chunkSize := uint64(detachment.GetChunkSize())
	blockSize := chunkSize + secretbox.Overhead

	if blockSize > 1<<20 {
		return errors.New("chunk size too large")
	}

	if paddedSize%blockSize != 0 {
		return errors.New("padded size is not a multiple of the chunk size")
	}

	fmt.Fprintf(os.Stderr, `Pond decryption:
  Original filename: %s
  Size: %d
  Padded size: %d
  Chunk size: %d
`, sanitiseForTerminal(detachment.GetFilename()), size, paddedSize, chunkSize)

	var key [32]byte
	var nonce [24]byte
	copy(key[:], detachment.Key)

	var read, written uint64
	buf := make([]byte, blockSize)
	var decrypted []byte

	for read < paddedSize {
		if _, err := io.ReadFull(os.Stdin, buf); err != nil {
			return err
		}

		read += uint64(len(buf))
		var ok bool
		decrypted, ok := secretbox.Open(decrypted[:0], buf, &nonce, &key)
		if !ok {
			return errors.New("decryption error")
		}

		incNonce(&nonce)

		todo := size - written
		if n := uint64(len(decrypted)); todo > n {
			todo = n
		}

		if _, err := os.Stdout.Write(decrypted[:todo]); err != nil {
			return err
		}

		written += todo
	}

	return nil
}

func incNonce(nonce *[24]byte) {
	s := 1
	for i, b := range nonce[:] {
		s += int(b)
		nonce[i] = byte(s)
		s >>= 8
	}
}

func sanitiseForTerminal(s string) string {
	var out []rune

	for _, r := range s {
		if r < 32 {
			r = ' '
		}
		out = append(out, r)
	}

	return string(out)
}
