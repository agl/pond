package main

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/pond/bbssig"
	pond "github.com/agl/pond/protos"
	"github.com/agl/pond/transport"
)

const (
	// maxQueue is the maximum number of messages that we'll queue for any
	// given user.
	maxQueue = 100
)

type Server struct {
	sync.Mutex

	baseDirectory string
	// accounts caches the groups for users to save loading them every
	// time.
	accounts map[string]*bbssig.Group
}

func NewServer(dir string) *Server {
	return &Server{
		baseDirectory: dir,
		accounts:      make(map[string]*bbssig.Group),
	}
}

func (s *Server) Process(conn *transport.Conn) {
	req := new(pond.Request)
	if err := conn.ReadProto(req); err != nil {
		log.Printf("Error from Read: %s", err)
		return
	}

	from := &conn.Peer
	var reply *pond.Reply
	var messageFetched string

	if req.NewAccount != nil {
		reply = s.newAccount(from, req.NewAccount)
	} else if req.Deliver != nil {
		reply = s.deliver(from, req.Deliver)
	} else if req.Fetch != nil {
		reply, messageFetched = s.fetch(from, req.Fetch)
	} else {
		reply = &pond.Reply{Status: pond.Reply_NO_REQUEST.Enum()}
	}

	if reply == nil {
		reply = &pond.Reply{}
	}

	if err := conn.WriteProto(reply); err != nil {
		log.Printf("Error from Write: %s", err)
		return
	}

	if err := conn.WaitForClose(); err != nil {
		log.Printf("Error from WaitForClose: %s", err)
		return
	}

	if len(messageFetched) > 0 {
		// We replied to a Fetch and the client successfully acked the
		// message by securely closing the connection. So we can mark
		// the message as delivered.
		s.confirmedDelivery(from, messageFetched)
	}
}

func (s *Server) accountPath(account *[32]byte) string {
	return filepath.Join(s.baseDirectory, "accounts", fmt.Sprintf("%x", account[:]))
}

func (s *Server) newAccount(from *[32]byte, req *pond.NewAccount) *pond.Reply {
	group, ok := new(bbssig.Group).Unmarshal(req.Group)
	if !ok {
		return &pond.Reply{Status: pond.Reply_PARSE_ERROR.Enum()}
	}

	path := s.accountPath(from)
	if _, err := os.Stat(path); err == nil {
		return &pond.Reply{Status: pond.Reply_IDENTITY_ALREADY_KNOWN.Enum()}
	}

	if err := os.MkdirAll(path, 0700); err != nil {
		log.Printf("failed to create directory: %s", err)
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
	}

	if err := ioutil.WriteFile(filepath.Join(path, "group"), req.Group, 0600); err != nil {
		log.Printf("failed to write group file: %s", err)
		goto err
	}

	s.Lock()
	s.accounts[string(from[:])] = group
	s.Unlock()

	return &pond.Reply{
		AccountCreated: &pond.AccountCreated{
			Details: &pond.AccountDetails{
				Queue:    proto.Uint32(0),
				MaxQueue: proto.Uint32(maxQueue),
			},
		},
	}

err:
	os.Remove(s.accountPath(from))
	return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
}

func (s *Server) getAccount(account *[32]byte) (*bbssig.Group, bool) {
	s.Lock()
	group, ok := s.accounts[string(account[:])]
	s.Unlock()

	if ok {
		return group, true
	}

	path := s.accountPath(account)
	if _, err := os.Stat(path); err != nil {
		return nil, false
	}

	groupPath := filepath.Join(path, "group")
	groupBytes, err := ioutil.ReadFile(groupPath)
	if err != nil {
		log.Print("group file doesn't exist for " + path)
		return nil, false
	}

	group, ok = new(bbssig.Group).Unmarshal(groupBytes)
	if !ok {
		log.Print("group corrupt for " + path)
		return nil, false
	}

	return group, true
}

func (s *Server) haveAccount(account *[32]byte) bool {
	s.Lock()
	_, ok := s.accounts[string(account[:])]
	s.Unlock()

	if ok {
		return true
	}

	path := s.accountPath(account)
	_, err := os.Stat(path)
	return err == nil
}

func (s *Server) deliver(from *[32]byte, del *pond.Delivery) *pond.Reply {
	var to [32]byte
	if len(del.To) != len(to) {
		return &pond.Reply{Status: pond.Reply_PARSE_ERROR.Enum()}
	}
	copy(to[:], del.To)

	group, ok := s.getAccount(&to)
	if !ok {
		return &pond.Reply{Status: pond.Reply_NO_SUCH_ADDRESS.Enum()}
	}

	sha := sha256.New()
	sha.Write(del.Message)
	digest := sha.Sum(nil)
	sha.Reset()

	if !group.Verify(digest, sha, del.Signature) {
		return &pond.Reply{Status: pond.Reply_DELIVERY_SIGNATURE_INVALID.Enum()}
	}

	serialized, _ := proto.Marshal(del)

	path := s.accountPath(&to)
	dir, err := os.Open(path)
	if err != nil {
		log.Printf("Failed to open %s: %s", dir, err)
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
	}
	defer dir.Close()
	ents, err := dir.Readdirnames(0)
	if err != nil {
		log.Printf("Failed to read %s: %s", dir, err)
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
	}
	if len(ents) > maxQueue {
		return &pond.Reply{Status: pond.Reply_MAILBOX_FULL.Enum()}
	}
	msgPath := filepath.Join(path, fmt.Sprintf("%x", digest))
	if err := ioutil.WriteFile(msgPath, serialized, 0600); err != nil {
		log.Printf("failed to write %s: %s", msgPath, err)
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
	}

	return &pond.Reply{}
}

func (s *Server) fetch(from *[32]byte, fetch *pond.Fetch) (*pond.Reply, string) {
	if !s.haveAccount(from) {
		return &pond.Reply{Status: pond.Reply_NO_ACCOUNT.Enum()}, ""
	}
	path := s.accountPath(from)

	dir, err := os.Open(path)
	if err != nil {
		log.Printf("Failed to open %s: %s", dir, err)
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}, ""
	}
	defer dir.Close()

	var del *pond.Delivery
	var name string
	var queueLen uint32

	// TODO: in the future we would look for a server announce message at
	// this point.

	for attempts := 0; attempts < 5; attempts++ {
		dir.Seek(0, 0)
		ents, err := dir.Readdir(0)
		if err != nil {
			log.Printf("Failed to read %s: %s", dir, err)
			return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}, ""
		}

		var minTime time.Time
		var minName string
		for _, ent := range ents {
			name := ent.Name()
			if len(name) != sha256.Size*2 {
				continue
			}
			if mtime := ent.ModTime(); minTime.IsZero() || mtime.Before(minTime) {
				minTime = mtime
				minName = name
			}
		}

		if len(minName) == 0 {
			// No messages at this time.
			return nil, ""
		}

		msgPath := filepath.Join(path, minName)
		var contents []byte
		if contents, err = ioutil.ReadFile(msgPath); err != nil && os.IsNotExist(err) {
			// The file could have been deleted by a concurrent
			// Fetch by the same user.
			continue
		} else if err != nil {
			log.Printf("Failed to read %s: %s", msgPath, err)
			return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}, ""
		}

		if len(contents) == 0 {
			log.Printf("Empty message file: %s. Deleting.", msgPath)
			os.Remove(msgPath)
			continue
		}

		del = new(pond.Delivery)
		if err := proto.Unmarshal(contents, del); err != nil {
			log.Printf("Corrupt message file: %s. Renaming out of the way.", msgPath)
			os.Rename(msgPath, msgPath+"-corrupt")
			del = nil
			continue
		}
		name = minName
		queueLen = uint32(len(ents)) - 1
		break
	}

	if len(name) == 0 {
		log.Printf("Failed to open any message file in %s", path)
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}, ""
	}

	fetched := &pond.Fetched{
		Signature:  del.Signature,
		Generation: del.Generation,
		Message:    del.Message,
		Details: &pond.AccountDetails{
			Queue:    proto.Uint32(queueLen),
			MaxQueue: proto.Uint32(0),
		},
	}

	return &pond.Reply{Fetched: fetched}, name
}

func (s *Server) confirmedDelivery(from *[32]byte, messageName string) {
	path := s.accountPath(from)
	msgPath := filepath.Join(path, messageName)

	if err := os.Remove(msgPath); err != nil && !os.IsNotExist(err) {
		log.Printf("Failed to delete message file in %s: %s", msgPath, err)
	}
}
