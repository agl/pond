package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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
	// sweepInterval is the period between when the server checks for
	// expired files.
	sweepInterval = 24 * time.Hour
	// fileLifetime is the amount of time that an uploaded file is kept
	// for.
	fileLifetime = 14 * 24 * time.Hour
	// maxRevocations is the maximum number of revocations that we'll store
	// on disk for any one account.
	maxRevocations = 100
	// maxFilesCount is the maximum number of uploads for a single account.
	maxFilesCount = 100
	// maxFilesSize is the maximum number of bytes for all uploads for a single account.
	maxFilesSize = 100 * 1024 * 1024
)

type Account struct {
	sync.Mutex

	server     *Server
	id         [32]byte
	group      *bbssig.Group
	filesValid bool
	filesCount int
	filesSize  int64
}

func NewAccount(s *Server, id *[32]byte) *Account {
	a := &Account{
		server: s,
	}
	copy(a.id[:], id[:])
	return a
}

func (a *Account) Group() *bbssig.Group {
	a.Lock()
	defer a.Unlock()

	if a.group != nil {
		return a.group
	}

	groupPath := filepath.Join(a.Path(), "group")
	groupBytes, err := ioutil.ReadFile(groupPath)
	if err != nil {
		log.Printf("Failed to load group from %s: %s", groupPath, err)
		return nil
	}

	var ok bool
	if a.group, ok = new(bbssig.Group).Unmarshal(groupBytes); !ok {
		log.Printf("Failed to parse group from %s", groupPath)
		return nil
	}

	return a.group
}

func (a *Account) Path() string {
	return filepath.Join(a.server.baseDirectory, "accounts", fmt.Sprintf("%x", a.id[:]))
}

func (a *Account) FilePath() string {
	return filepath.Join(a.Path(), "files")
}

func (a *Account) RevocationPath() string {
	return filepath.Join(a.Path(), "revocations")
}

func (a *Account) LoadFileInfo() bool {
	a.Lock()
	defer a.Unlock()

	return a.loadFileInfo()
}

func (a *Account) loadFileInfo() bool {
	if a.filesValid {
		return true
	}

	path := filepath.Join(a.Path(), "files")
	dir, err := os.Open(path)
	if err != nil {
		if err = os.Mkdir(path, 0700); err != nil {
			log.Printf("Failed to create files directory %s: %s", path, err)
			return false
		}
		dir, err = os.Open(path)
	}
	if err != nil {
		log.Printf("Failed to open files directory %s: %s", path, err)
		return false
	}
	defer dir.Close()

	ents, err := dir.Readdir(0)
	if err != nil {
		log.Printf("Failed to read %s: %s", path, err)
		return false
	}

	for _, ent := range ents {
		if ent.IsDir() {
			continue
		}
		a.filesCount++
		a.filesSize += ent.Size()
	}

	a.filesValid = true
	return true
}

func (a *Account) ReserveFile(newFile bool, size int64) bool {
	a.Lock()
	defer a.Unlock()

	if !a.loadFileInfo() {
		return false
	}

	newCount := a.filesCount
	if newFile {
		newCount++
		if newCount < a.filesCount {
			return false
		}
	}

	newSize := a.filesSize + size
	if newSize < a.filesSize {
		return false
	}

	if newCount > maxFilesCount || newSize > maxFilesSize {
		return false
	}

	a.filesCount = newCount
	a.filesSize = newSize
	return true
}

func (a *Account) ReleaseFile(removedFile bool, size int64) {
	a.Lock()
	defer a.Unlock()

	if !a.loadFileInfo() {
		return
	}

	if removedFile && a.filesCount > 0 {
		a.filesCount--
	}
	if a.filesSize >= size {
		a.filesSize -= size
	}
}

type Server struct {
	sync.Mutex

	baseDirectory string
	// accounts caches the groups for users to save loading them every
	// time.
	accounts map[string]*Account
	// lastSweepTime is the time when the server last performed a sweep for
	// expired files.
	lastSweepTime time.Time
}

func NewServer(dir string) *Server {
	return &Server{
		baseDirectory: dir,
		accounts:      make(map[string]*Account),
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
	} else if req.Upload != nil {
		reply = s.upload(from, conn, req.Upload)
		if reply == nil {
			// Connection will be handled by upload.
			return
		}
	} else if req.Download != nil {
		reply = s.download(conn, req.Download)
		if reply == nil {
			// Connection will be handled by download.
			return
		}
	} else if req.Revocation != nil {
		reply = s.revocation(from, req.Revocation)
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

	s.Lock()
	needSweep := false
	now := time.Now()
	if s.lastSweepTime.IsZero() || now.Before(s.lastSweepTime) || now.Sub(s.lastSweepTime) > sweepInterval {
		s.lastSweepTime = now
		needSweep = true
	}
	s.Unlock()

	if needSweep {
		s.sweep()
	}
}

func notLowercaseHex(r rune) bool {
	return (r < '0' || r > '9') && (r < 'a' || r > 'f')
}

func (s *Server) sweep() {
	log.Printf("Performing sweep for old files")
	now := time.Now()

	accountsPath := filepath.Join(s.baseDirectory, "accounts")
	accountsDir, err := os.Open(accountsPath)
	if err != nil {
		log.Printf("Failed to open %s: %s", accountsPath, err)
		return
	}
	defer accountsDir.Close()

	ents, err := accountsDir.Readdir(0)
	if err != nil {
		log.Printf("Failed to read %s: %s", accountsPath, err)
		return
	}

	for _, ent := range ents {
		name := ent.Name()
		if len(name) == 64 && strings.IndexFunc(name, notLowercaseHex) == -1 {
			filesPath := filepath.Join(accountsPath, name, "files")
			filesDir, err := os.Open(filesPath)
			if os.IsNotExist(err) {
				continue
			} else if err != nil {
				log.Printf("Failed to open %s: %s", filesPath, err)
				continue
			}

			filesEnts, err := filesDir.Readdir(0)
			if err == nil {
				for _, fileEnt := range filesEnts {
					name := fileEnt.Name()
					if len(name) > 0 && strings.IndexFunc(name, notLowercaseHex) == -1 {
						mtime := fileEnt.ModTime()
						if now.After(mtime) && now.Sub(mtime) > fileLifetime {
							if err := os.Remove(filepath.Join(filesPath, name)); err != nil {
								log.Printf("Failed to delete file: %s", err)
							}
						}
					}
				}
			} else {
				log.Printf("Failed to read %s: %s", filesPath, err)
			}

			filesDir.Close()
		}
	}
}

func (s *Server) newAccount(from *[32]byte, req *pond.NewAccount) *pond.Reply {
	account := NewAccount(s, from)

	var ok bool
	account.group, ok = new(bbssig.Group).Unmarshal(req.Group)
	if !ok {
		return &pond.Reply{Status: pond.Reply_PARSE_ERROR.Enum()}
	}

	path := account.Path()
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
	s.accounts[string(from[:])] = account
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
	os.Remove(account.Path())
	return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
}

func (s *Server) getAccount(id *[32]byte) (*Account, bool) {
	key := string(id[:])

	s.Lock()
	account, ok := s.accounts[key]
	s.Unlock()

	if ok {
		return account, true
	}

	account = NewAccount(s, id)
	path := account.Path()
	if _, err := os.Stat(path); err != nil {
		return nil, false
	}

	s.Lock()
	if other, ok := s.accounts[key]; ok {
		// We raced with another goroutine to create this and they won.
		account = other
	} else {
		s.accounts[key] = account
	}
	s.Unlock()

	return account, true
}

func (s *Server) deliver(from *[32]byte, del *pond.Delivery) *pond.Reply {
	var to [32]byte
	if len(del.To) != len(to) {
		return &pond.Reply{Status: pond.Reply_PARSE_ERROR.Enum()}
	}
	copy(to[:], del.To)

	account, ok := s.getAccount(&to)
	if !ok {
		return &pond.Reply{Status: pond.Reply_NO_SUCH_ADDRESS.Enum()}
	}

	revPath := filepath.Join(account.RevocationPath(), fmt.Sprintf("%08x", *del.Generation))
	revBytes, err := ioutil.ReadFile(revPath)
	if err == nil {
		var revocation pond.SignedRevocation
		if err := proto.Unmarshal(revBytes, &revocation); err != nil {
			log.Printf("Failed to parse revocation from file %s: %s", revPath, err)
			return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
		}
		return &pond.Reply{Status: pond.Reply_GENERATION_REVOKED.Enum(), Revocation: &revocation}
	}

	sha := sha256.New()
	sha.Write(del.Message)
	digest := sha.Sum(nil)
	sha.Reset()

	group := account.Group()
	if group == nil {
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
	}

	if !group.Verify(digest, sha, del.Signature) {
		return &pond.Reply{Status: pond.Reply_DELIVERY_SIGNATURE_INVALID.Enum()}
	}

	serialized, _ := proto.Marshal(del)

	path := account.Path()
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

const announcePrefix = "announce-"

func (s *Server) fetch(from *[32]byte, fetch *pond.Fetch) (*pond.Reply, string) {
	account, ok := s.getAccount(from)
	if !ok {
		return &pond.Reply{Status: pond.Reply_NO_ACCOUNT.Enum()}, ""
	}
	path := account.Path()

	dir, err := os.Open(path)
	if err != nil {
		log.Printf("Failed to open %s: %s", dir, err)
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}, ""
	}
	defer dir.Close()

	var del *pond.Delivery
	var announce *pond.Message
	var isAnnounce bool
	var name string
	var queueLen uint32

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
			if len(name) != sha256.Size*2 &&
				(!strings.HasPrefix(name, announcePrefix) || len(name) != len(announcePrefix)+8) {
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

		if strings.HasPrefix(minName, announcePrefix) {
			isAnnounce = true
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

		var unmarshaled proto.Message
		if isAnnounce {
			announce = new(pond.Message)
			unmarshaled = announce
		} else {
			del = new(pond.Delivery)
			unmarshaled = del
		}

		if err := proto.Unmarshal(contents, unmarshaled); err != nil {
			log.Printf("Corrupt message file: %s (%s). Renaming out of the way.", msgPath, err)
			if err := os.Rename(msgPath, msgPath+"-corrupt"); err != nil {
				log.Printf("Failed to rename file: %s", err)
			}
			del = nil
			announce = nil
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

	if isAnnounce {
		serverAnnounce := &pond.ServerAnnounce{
			Message: announce,
		}

		return &pond.Reply{Announce: serverAnnounce}, name
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
	account, ok := s.getAccount(from)
	if !ok {
		return
	}
	path := account.Path()
	msgPath := filepath.Join(path, messageName)

	if err := os.Remove(msgPath); err != nil && !os.IsNotExist(err) {
		log.Printf("Failed to delete message file in %s: %s", msgPath, err)
	}
}

func (s *Server) upload(from *[32]byte, conn *transport.Conn, upload *pond.Upload) *pond.Reply {
	account, ok := s.getAccount(from)
	if !ok {
		return &pond.Reply{Status: pond.Reply_NO_ACCOUNT.Enum()}
	}

	if *upload.Size < 1 {
		return &pond.Reply{Status: pond.Reply_PARSE_ERROR.Enum()}
	}

	path := filepath.Join(account.FilePath(), strconv.FormatUint(*upload.Id, 16))

	if !account.LoadFileInfo() {
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Printf("Failed to create file %s: %s", path, err)
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
	}
	defer file.Close()

	offset, err := file.Seek(0, 2 /* from end */)

	switch {
	case offset == *upload.Size:
		return &pond.Reply{Status: pond.Reply_FILE_COMPLETE.Enum()}
	case offset > *upload.Size:
		return &pond.Reply{Status: pond.Reply_FILE_LARGER_THAN_SIZE.Enum()}
	}

	size := *upload.Size - offset
	if !account.ReserveFile(offset > 0, size) {
		return &pond.Reply{Status: pond.Reply_OVER_QUOTA.Enum()}
	}

	var resume *int64
	if offset > 0 {
		resume = proto.Int64(offset)
	}

	reply := &pond.Reply{
		Upload: &pond.UploadReply{
			Resume: resume,
		},
	}
	if err := conn.WriteProto(reply); err != nil {
		return nil
	}

	n, err := io.Copy(file, io.LimitReader(conn, size))
	switch {
	case n == 0:
		os.Remove(path)
		account.ReleaseFile(true, size)
	case n < size:
		account.ReleaseFile(false, size-n)
	case n == size:
		if err == nil {
			conn.Write([]byte{0})
		}
	case n > size:
		panic("impossible")
	}

	return nil
}

func (s *Server) download(conn *transport.Conn, download *pond.Download) *pond.Reply {
	var from [32]byte
	if len(download.From) != len(from) {
		return &pond.Reply{Status: pond.Reply_PARSE_ERROR.Enum()}
	}
	copy(from[:], download.From)

	account, ok := s.getAccount(&from)
	if !ok {
		return &pond.Reply{Status: pond.Reply_NO_SUCH_ADDRESS.Enum()}
	}

	path := filepath.Join(account.FilePath(), strconv.FormatUint(*download.Id, 16))
	file, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return &pond.Reply{Status: pond.Reply_NO_SUCH_FILE.Enum()}
	}
	defer file.Close()

	fi, err := file.Stat()
	if err != nil {
		log.Printf("failed to stat file %s: %s", path, err)
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
	}
	size := fi.Size()

	if download.Resume != nil {
		if *download.Resume < 1 {
			return &pond.Reply{Status: pond.Reply_PARSE_ERROR.Enum()}
		}

		if size <= *download.Resume {
			return &pond.Reply{Status: pond.Reply_RESUME_PAST_END_OF_FILE.Enum()}
		}
		pos, err := file.Seek(*download.Resume, 0 /* from start */)
		if pos != *download.Resume || err != nil {
			log.Printf("failed to seek to %d in %s: got %d %s", *download.Resume, path, pos, err)
			return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
		}
	}

	reply := &pond.Reply{
		Download: &pond.DownloadReply{
			Size: proto.Int64(size),
		},
	}
	if err := conn.WriteProto(reply); err != nil {
		return nil
	}

	io.Copy(conn, file)
	return nil
}

func (s *Server) revocation(from *[32]byte, signedRevocation *pond.SignedRevocation) *pond.Reply {
	account, ok := s.getAccount(from)
	if !ok {
		return &pond.Reply{Status: pond.Reply_NO_ACCOUNT.Enum()}
	}

	revocation, ok := new(bbssig.Revocation).Unmarshal(signedRevocation.Revocation.Revocation)
	if !ok {
		return &pond.Reply{Status: pond.Reply_CANNOT_PARSE_REVOCATION.Enum()}
	}

	// First check that the account doesn't have too many revocations
	// stored.

	revPath := account.RevocationPath()
	os.MkdirAll(revPath, 0777)

	revDir, err := os.Open(revPath)
	if err != nil {
		log.Printf("Failed to open %s: %s", revPath, err)
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
	}
	defer revDir.Close()

	ents, err := revDir.Readdir(0)
	if err != nil {
		log.Printf("Failed to read %s: %s", revDir, err)
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
	}

	if len(ents) > maxRevocations {
		// Delete the oldest revocation.
		names := make([]string, 0, len(ents))
		for _, ent := range ents {
			names = append(names, ent.Name())
		}
		sort.Strings(names)
		path := filepath.Join(revPath, names[0])
		if err := os.Remove(path); err != nil {
			log.Printf("Failed to remove %s: %s", path, err)
			return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
		}
	}

	path := filepath.Join(revPath, fmt.Sprintf("%08x", *signedRevocation.Revocation.Generation))
	revBytes, err := proto.Marshal(signedRevocation)
	if err != nil {
		log.Printf("Failed to serialise revocation: %s", err)
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
	}

	if err := ioutil.WriteFile(path, revBytes, 0666); err != nil {
		log.Printf("Failed to write revocation file: %s", err)
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
	}

	group := account.Group()
	groupCopy, _ := new(bbssig.Group).Unmarshal(group.Marshal())
	groupCopy.Update(revocation)

	account.Lock()
	defer account.Unlock()

	account.group = groupCopy
	groupPath := filepath.Join(account.Path(), "group")
	if err := ioutil.WriteFile(groupPath, groupCopy.Marshal(), 0600); err != nil {
		log.Printf("failed to write group file: %s", err)
	}

	return nil
}
