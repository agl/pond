package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"time"

	pond "github.com/agl/pond/protos"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/nacl/secretbox"
)

var backgroundCanceledError = errors.New("background task canceled")

func (c *client) startEncryption(id uint64, outPath, inPath string) (cancel func()) {
	killChan := make(chan bool, 1)
	go func() {
		var detachment *pond.Message_Detachment
		var out *os.File
		var err error
		if out, err = os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600); err != nil {
			err = errors.New("failed to open output: " + err.Error())
		} else {
			defer out.Close()
			detachment, err = saveEncrypted(c.rand, c.backgroundChan, out, id, inPath, killChan)
		}
		if detachment != nil {
			c.backgroundChan <- DetachmentComplete{id, detachment}
		} else {
			os.Remove(outPath)
			c.backgroundChan <- DetachmentError{id, err}
		}
	}()
	return func() {
		killChan <- true
	}
}

func (c *client) startDecryption(id uint64, outPath, inPath string, detachment *pond.Message_Detachment) (cancel func()) {
	killChan := make(chan bool, 1)
	go func() {
		var in *os.File
		var err error
		if in, err = os.Open(inPath); err != nil {
			err = errors.New("failed to open input: " + err.Error())
		} else {
			defer in.Close()
			err = saveDecrypted(c.backgroundChan, outPath, id, in, detachment, killChan)
		}
		if err != nil {
			c.backgroundChan <- DetachmentError{id, err}
		} else {
			c.backgroundChan <- DetachmentComplete{id, nil}
		}
	}()
	return func() {
		killChan <- true
	}
}

func (c *client) buildDetachmentURL(id uint64) string {
	u, err := url.Parse(c.server)
	if err != nil {
		panic("own server failed to parse as URL")
	}

	u.Path = fmt.Sprintf("/%x/%x", c.identityPublic[:], id)
	return u.String()
}

func (c *client) startUpload(id uint64, inPath string) (cancel func()) {
	killChan := make(chan bool, 1)
	go func() {
		var detachment *pond.Message_Detachment
		var tmp *os.File
		var err error
		if tmp, err = ioutil.TempFile("" /* default tmp dir */, "pond-upload-"); err != nil {
			err = errors.New("failed to create temp file: " + err.Error())
		} else {
			os.Remove(tmp.Name())
			defer tmp.Close()
			detachment, err = saveEncrypted(c.rand, c.backgroundChan, tmp, id, inPath, killChan)
			if err == nil {
				err = c.uploadDetachment(c.backgroundChan, tmp, id, killChan)
			}
		}
		if err == nil {
			detachment.Url = proto.String(c.buildDetachmentURL(id))
			c.log.Printf("Finished upload of %s", *detachment.Url)
			c.backgroundChan <- DetachmentComplete{id, detachment}
		} else {
			c.backgroundChan <- DetachmentError{id, err}
		}
	}()
	return func() {
		killChan <- true
	}
}

func (c *client) startDownload(id uint64, outPath string, detachment *pond.Message_Detachment) (cancel func()) {
	killChan := make(chan bool, 1)
	go func() {
		var tmp *os.File
		var err error
		if tmp, err = ioutil.TempFile("" /* default tmp dir */, "pond-download-"); err != nil {
			err = errors.New("failed to create temp file: " + err.Error())
		} else {
			os.Remove(tmp.Name())
			defer tmp.Close()
			err = c.downloadDetachment(c.backgroundChan, tmp, id, *detachment.Url, killChan)
			if err == nil {
				_, err := tmp.Seek(0, 0 /* from start */)
				if err == nil {
					err = saveDecrypted(c.backgroundChan, outPath, id, tmp, detachment, killChan)
				}
			}
		}
		if err == nil {
			c.backgroundChan <- DetachmentComplete{id, nil}
		} else {
			c.backgroundChan <- DetachmentError{id, err}
		}
	}()
	return func() {
		killChan <- true
	}
}

type DetachmentProgress struct {
	id          uint64
	done, total uint64
	status      string
}

type DetachmentError struct {
	id  uint64
	err error
}

type DetachmentComplete struct {
	id         uint64
	detachment *pond.Message_Detachment
}

const defaultDetachmentBlockSize = 16384 - secretbox.Overhead

func saveEncrypted(rand io.Reader, c chan interface{}, out io.Writer, id uint64, inPath string, killChan chan bool) (*pond.Message_Detachment, error) {
	in, err := os.Open(inPath)
	if err != nil {
		return nil, errors.New("failed to open input: " + err.Error())
	}
	defer in.Close()

	var size int64
	if fileInfo, err := in.Stat(); err == nil {
		size = fileInfo.Size()
	}

	var key [32]byte
	var nonce [24]byte

	if _, err := io.ReadFull(rand, key[:]); err != nil {
		panic(err)
	}

	blockSize := defaultDetachmentBlockSize
	buf := make([]byte, blockSize)

	var fileSize, bytesOut uint64
	var eof bool
	var boxBuf []byte
	var lastUpdate time.Time

	for {
		if !eof {
			n, err := io.ReadFull(in, buf)
			switch err {
			case nil:
				break
			case io.ErrUnexpectedEOF, io.EOF:
				eof = true
			default:
				return nil, errors.New("failed to read from source file: " + err.Error())
			}
			fileSize += uint64(n)
		}
		boxBuf = secretbox.Seal(boxBuf[:0], buf, &nonce, &key)

		if _, err := out.Write(boxBuf); err != nil {
			return nil, errors.New("failed to write to destination: " + err.Error())
		}
		bytesOut += uint64(len(boxBuf))

		// Stop when we've read all of the file and have hit a power of
		// two.
		if eof && (bytesOut&(bytesOut-1)) == 0 {
			break
		}

		incNonce(&nonce)

		now := time.Now()
		if size > 0 && (lastUpdate.IsZero() || now.Sub(lastUpdate) > 500*time.Millisecond) {
			lastUpdate = now
			select {
			case c <- DetachmentProgress{
				id:     id,
				done:   fileSize,
				total:  uint64(size),
				status: "encrypting",
			}:
				break
			default:
			}
		}

		select {
		case <-killChan:
			return nil, backgroundCanceledError
		default:
			break
		}
	}

	return &pond.Message_Detachment{
		Filename:   proto.String(filepath.Base(inPath)),
		Size:       proto.Uint64(fileSize),
		PaddedSize: proto.Uint64(bytesOut),
		ChunkSize:  proto.Uint32(uint32(blockSize)),
		Key:        key[:],
	}, nil
}

func saveDecrypted(c chan interface{}, outPath string, id uint64, in *os.File, detachment *pond.Message_Detachment, killChan chan bool) error {
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return errors.New("failed to open output: " + err.Error())
	}
	defer out.Close()

	var key [32]byte
	var nonce [24]byte

	blockSize := *detachment.ChunkSize + secretbox.Overhead
	if blockSize > 1<<20 {
		return errors.New("chunk size too large")
	}

	copy(key[:], detachment.Key)

	var bytesIn, bytesOut uint64
	buf := make([]byte, blockSize)
	var decrypted []byte
	var lastUpdate time.Time

BlockLoop:
	for {
		n, err := io.ReadFull(in, buf)
		switch err {
		case nil:
			break
		case io.ErrUnexpectedEOF, io.EOF:
			break BlockLoop
		default:
			return errors.New("failed to read from source: " + err.Error())
		}

		bytesIn += uint64(n)
		var ok bool
		decrypted, ok = secretbox.Open(decrypted[:0], buf, &nonce, &key)
		if !ok {
			os.Remove(outPath)
			return errors.New("input corrupt")
		}

		if bytesOut != *detachment.Size {
			if n := bytesOut + uint64(len(decrypted)); n > *detachment.Size {
				decrypted = decrypted[:*detachment.Size-bytesOut]
			}
			bytesOut += uint64(len(decrypted))

			if _, err := out.Write(decrypted); err != nil {
				return errors.New("failed to write to destination: " + err.Error())
			}
		}

		if bytesIn > *detachment.PaddedSize {
			// This means that we downloaded more bytes than we
			// expected.
			break
		}

		incNonce(&nonce)

		now := time.Now()
		if lastUpdate.IsZero() || now.Sub(lastUpdate) > 500*time.Millisecond {
			lastUpdate = now
			select {
			case c <- DetachmentProgress{
				id:     id,
				done:   bytesIn,
				total:  *detachment.PaddedSize,
				status: "decrypting",
			}:
				break
			default:
			}
		}

		select {
		case <-killChan:
			os.Remove(outPath)
			return backgroundCanceledError
		default:
			break
		}
	}

	if bytesIn != *detachment.PaddedSize {
		return errors.New("input truncated")
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
