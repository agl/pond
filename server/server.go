package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
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

	"github.com/agl/ed25519"
	"github.com/agl/pond/bbssig"
	pond "github.com/agl/pond/protos"
	"github.com/agl/pond/transport"
	"github.com/golang/protobuf/proto"
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
	// maxFilesCount is the default, maximum number of uploads for a single
	// account. This can be overridden by a "quota-files" file in the
	// account directory.
	maxFilesCount = 100
	// maxFilesMB is the default, maximum number of megabytes for all
	// uploads for a single account. This can be overridden by a
	// "quota-megabytes" file in the account directory.
	maxFilesMB = 100
	// hmacValueMask is the bottom 63 bits. This is used for HMAC values
	// where the HMAC is only 63 bits wide and the MSB is used to signal
	// whether a revocation was used or not.
	hmacValueMask = 0x7fffffffffffffff
	// hmacMaxLength is the maximum size, in bytes, of an HMAC strike
	// file. This is 256K entries.
	hmacMaxLength = 2 * 1024 * 1024
)

type Account struct {
	sync.Mutex

	server       *Server
	id           [32]byte
	group        *bbssig.Group
	filesValid   bool
	filesCount   int64
	filesSize    int64
	hmacKey      [32]byte
	hmacKeyValid bool
}

func NewAccount(s *Server, id *[32]byte) *Account {
	a := &Account{
		server: s,
	}
	copy(a.id[:], id[:])
	return a
}

func (a *Account) HMACKey() (*[32]byte, bool) {
	a.Lock()
	defer a.Unlock()

	if a.hmacKeyValid {
		return &a.hmacKey, true
	}

	keyPath := a.HMACKeyPath()
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, false
	}
	if len(keyBytes) != len(a.hmacKey) {
		log.Printf("Incorrect hmacKey length for %s", keyPath)
		return nil, false
	}

	copy(a.hmacKey[:], keyBytes)
	a.hmacKeyValid = true

	return &a.hmacKey, true
}

// findHMAC finds v in hmacBytes. If found it returns zero and true. Otherwise
// it returns the index where the value should be inserted and false.
func findHMAC(hmacBytes []byte, v uint64) (insertIndex int, msb bool, found bool) {
	v &= hmacValueMask

	searchMin, searchMax := 0, len(hmacBytes)/8-1
	for searchMin <= searchMax {
		midPoint := searchMin + ((searchMax - searchMin) / 2)
		midValue := binary.LittleEndian.Uint64(hmacBytes[midPoint*8:])
		maskedMidValue := midValue & hmacValueMask

		switch {
		case maskedMidValue > v:
			searchMax = midPoint - 1
		case maskedMidValue < v:
			searchMin = midPoint + 1
		default:
			return 0, maskedMidValue != midValue, true
		}
	}

	return searchMin, false, false
}

func readHMACs(path string, overhead int) (f *os.File, hmacBytes []byte, ok bool) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		log.Printf("Failed to open HMAC strike file %s", err)
		return
	}

	fi, err := f.Stat()
	var size int64
	if err != nil {
		log.Printf("Failed to stat HMAC strike file %s", err)
		goto err
	}

	size = fi.Size()

	if size%8 != 0 {
		log.Printf("HMAC strike file is not a multiple of 8: %s", path)
		goto err
	}

	if size > hmacMaxLength {
		log.Printf("HMAC strike file is too large: %s", path)
		goto err
	}

	hmacBytes = make([]byte, size, size+int64(overhead))

	if _, err := io.ReadFull(f, hmacBytes); err != nil {
		log.Printf("Failed to read HMAC strike file %s", err)
		goto err
	}

	ok = true
	return

err:
	f.Close()
	return
}

type hmacInsertResult int

const (
	hmacFresh hmacInsertResult = iota
	hmacUsed
	hmacRevoked
)

func insertHMAC(path string, v uint64) (result hmacInsertResult, ok bool) {
	f, hmacBytes, ok := readHMACs(path, 0)
	if !ok {
		return hmacUsed, false
	}
	defer f.Close()

	insertIndex, msb, found := findHMAC(hmacBytes, v)
	if found {
		if msb {
			return hmacRevoked, true
		}
		return hmacUsed, true
	}

	var serialised [8]byte
	binary.LittleEndian.PutUint64(serialised[:], v)

	f.Seek(int64(insertIndex)*8, 0)
	if _, err := f.Write(serialised[:]); err != nil {
		log.Printf("Failed to write to HMAC file: %s", err)
		return hmacUsed, false
	}
	if _, err := f.Write(hmacBytes[insertIndex*8:]); err != nil {
		log.Printf("Failed to write to HMAC file: %s", err)
		return hmacUsed, false
	}

	return hmacFresh, true
}

func (a *Account) InsertHMAC(v uint64) (result hmacInsertResult, ok bool) {
	if v&hmacValueMask != v {
		panic("unmasked value given to InsertHMAC")
	}

	a.Lock()
	defer a.Unlock()

	return insertHMAC(a.HMACValuesPath(), v)
}

type hmacVector []byte

func (hmacs hmacVector) Len() int {
	return len(hmacs) / 8
}

func (hmacs hmacVector) Less(i, j int) bool {
	iVal := binary.LittleEndian.Uint64(hmacs[8*i:]) & hmacValueMask
	jVal := binary.LittleEndian.Uint64(hmacs[8*j:]) & hmacValueMask

	return iVal < jVal
}

func (hmacs hmacVector) Swap(i, j int) {
	var tmp [8]byte
	copy(tmp[:], hmacs[8*i:])
	copy(hmacs[i*8:(i+1)*8], hmacs[8*j:])
	copy(hmacs[j*8:], tmp[:])
}

func insertHMACs(path string, vs []uint64) bool {
	switch len(vs) {
	case 0:
		return true
	case 1:
		_, ok := insertHMAC(path, vs[0])
		return ok
	}

	f, hmacBytes, ok := readHMACs(path, 8*len(vs))
	if !ok {
		return false
	}
	defer f.Close()

	var serialised [8]byte
	for _, v := range vs {
		if _, _, found := findHMAC(hmacBytes, v); found {
			continue
		}
		binary.LittleEndian.PutUint64(serialised[:], v)
		hmacBytes = append(hmacBytes, serialised[:]...)
	}

	sort.Sort(hmacVector(hmacBytes))

	f.Seek(0, 0)
	if _, err := f.Write(hmacBytes); err != nil {
		log.Printf("Failed to write to HMAC file: %s", err)
		return false
	}

	return true
}

func (a *Account) InsertHMACs(vs []uint64) bool {
	a.Lock()
	defer a.Unlock()

	return insertHMACs(a.HMACValuesPath(), vs)
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

func (a *Account) HMACKeyPath() string {
	return filepath.Join(a.Path(), "hmackey")
}

func (a *Account) HMACValuesPath() string {
	return filepath.Join(a.Path(), "hmacstrike")
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

func (a *Account) numericConfig(name string, defValue int64) (int64, error) {
	path := filepath.Join(a.Path(), name)
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return defValue, err
		}
		return defValue, nil
	}
	return strconv.ParseInt(strings.TrimSpace(string(contents)), 10, 64)
}

func (a *Account) QuotaBytes() (int64, error) {
	mb, err := a.numericConfig("quota-megabytes", maxFilesMB)
	return 1024 * 1024 * mb, err
}

func (a *Account) QuotaFiles() (int64, error) {
	return a.numericConfig("quota-files", maxFilesCount)
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

	maxFiles, err := a.QuotaFiles()
	if err != nil {
		log.Printf("Error from QuotaFiles for %x: %s", a.id[:], err)
	}

	maxBytes, err := a.QuotaBytes()
	if err != nil {
		log.Printf("Error from QuotaBytes for %x: %s", a.id[:], err)
	}

	if newCount > maxFiles || newSize > maxBytes {
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
	lastSweepTime     time.Time
	allowRegistration bool
}

func NewServer(dir string, allowRegistration bool) *Server {
	return &Server{
		baseDirectory:     dir,
		accounts:          make(map[string]*Account),
		allowRegistration: allowRegistration,
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

	switch {
	case req.NewAccount != nil:
		reply = s.newAccount(from, req.NewAccount)
	case req.Deliver != nil:
		reply = s.deliver(from, req.Deliver)
	case req.Fetch != nil:
		reply, messageFetched = s.fetch(from, req.Fetch)
	case req.Upload != nil:
		reply = s.upload(from, conn, req.Upload)
		if reply == nil {
			// Connection will be handled by upload.
			return
		}
	case req.Download != nil:
		reply = s.download(conn, req.Download)
		if reply == nil {
			// Connection will be handled by download.
			return
		}
	case req.Revocation != nil:
		reply = s.revocation(from, req.Revocation)
	case req.HmacSetup != nil:
		reply = s.hmacSetup(from, req.HmacSetup)
	case req.HmacStrike != nil:
		reply = s.hmacStrike(from, req.HmacStrike)
	default:
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
		if len(name) != 64 || strings.IndexFunc(name, notLowercaseHex) != -1 {
			continue
		}

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

func (s *Server) newAccount(from *[32]byte, req *pond.NewAccount) *pond.Reply {
	account := NewAccount(s, from)

	if !s.allowRegistration {
		log.Printf("rejected registration of new account")
		return &pond.Reply{Status: pond.Reply_REGISTRATION_DISABLED.Enum()}
	}

	var ok bool
	account.group, ok = new(bbssig.Group).Unmarshal(req.Group)
	if !ok {
		return &pond.Reply{Status: pond.Reply_PARSE_ERROR.Enum()}
	}

	path := account.Path()
	if _, err := os.Stat(path); err == nil {
		return &pond.Reply{Status: pond.Reply_IDENTITY_ALREADY_KNOWN.Enum()}
	}

	if _, ok := new(bbssig.Group).Unmarshal(req.Group); !ok {
		return &pond.Reply{Status: pond.Reply_PARSE_ERROR.Enum()}
	}

	if l := len(req.HmacKey); l != 0 && l != len(account.hmacKey) {
		return &pond.Reply{Status: pond.Reply_PARSE_ERROR.Enum()}
	}

	if err := os.MkdirAll(path, 0700); err != nil {
		log.Printf("failed to create directory: %s", err)
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
	}

	if err := ioutil.WriteFile(filepath.Join(path, "group"), req.Group, 0600); err != nil {
		log.Printf("failed to write group file: %s", err)
		goto err
	}

	if len(req.HmacKey) > 0 {
		if err := ioutil.WriteFile(account.HMACKeyPath(), req.HmacKey, 0600); err != nil {
			log.Printf("failed to write HMAC key file: %s", err)
			goto err
		}
		copy(account.hmacKey[:], req.HmacKey)
		account.hmacKeyValid = true
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

func authenticateDeliveryWithGroupSignature(account *Account, del *pond.Delivery) (*pond.Reply, bool) {
	revPath := filepath.Join(account.RevocationPath(), fmt.Sprintf("%08x", *del.Generation))
	revBytes, err := ioutil.ReadFile(revPath)
	if err == nil {
		var revocation pond.SignedRevocation
		if err := proto.Unmarshal(revBytes, &revocation); err != nil {
			log.Printf("Failed to parse revocation from file %s: %s", revPath, err)
			return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}, false
		}

		// maxRevocationBytes is the maximum number of bytes that we'll
		// take up in extra revocations.
		const maxRevocationBytes = 14000
		revLength := len(revBytes)
		var extraRevocations []*pond.SignedRevocation
		for gen := *del.Generation + 1; revLength < maxRevocationBytes; gen++ {
			revPath := filepath.Join(account.RevocationPath(), fmt.Sprintf("%08x", gen))
			revBytes, err := ioutil.ReadFile(revPath)
			if err != nil {
				break
			}

			var revocation pond.SignedRevocation
			if err := proto.Unmarshal(revBytes, &revocation); err != nil {
				log.Printf("Failed to parse revocation from file %s: %s", revPath, err)
				break
			}

			extraRevocations = append(extraRevocations, &revocation)
			revLength += len(revBytes)
		}

		return &pond.Reply{Status: pond.Reply_GENERATION_REVOKED.Enum(), Revocation: &revocation, ExtraRevocations: extraRevocations}, false
	}

	sha := sha256.New()
	sha.Write(del.Message)
	digest := sha.Sum(nil)
	sha.Reset()

	group := account.Group()
	if group == nil {
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}, false
	}

	if !group.Verify(digest, sha, del.GroupSignature) {
		return &pond.Reply{Status: pond.Reply_DELIVERY_SIGNATURE_INVALID.Enum()}, false
	}

	return nil, true
}

func authenticateDeliveryWithHMAC(account *Account, del *pond.Delivery) (*pond.Reply, bool) {
	if len(del.OneTimePublicKey) != ed25519.PublicKeySize || len(del.OneTimeSignature) != ed25519.SignatureSize {
		return &pond.Reply{Status: pond.Reply_PARSE_ERROR.Enum()}, false
	}

	hmacKey, ok := account.HMACKey()
	if !ok {
		return &pond.Reply{Status: pond.Reply_HMAC_NOT_SETUP.Enum()}, false
	}

	if x := *del.HmacOfPublicKey; x&hmacValueMask != x {
		return &pond.Reply{Status: pond.Reply_PARSE_ERROR.Enum()}, false
	}

	h := hmac.New(sha256.New, hmacKey[:])
	h.Write(del.OneTimePublicKey)
	digestFull := h.Sum(nil)
	digest := binary.LittleEndian.Uint64(digestFull) & hmacValueMask

	if digest != *del.HmacOfPublicKey {
		return &pond.Reply{Status: pond.Reply_HMAC_INCORRECT.Enum()}, false
	}

	var publicKey [ed25519.PublicKeySize]byte
	var sig [ed25519.SignatureSize]byte
	copy(publicKey[:], del.OneTimePublicKey)
	copy(sig[:], del.OneTimeSignature)

	if !ed25519.Verify(&publicKey, del.Message, &sig) {
		return &pond.Reply{Status: pond.Reply_DELIVERY_SIGNATURE_INVALID.Enum()}, false
	}

	result, ok := account.InsertHMAC(digest)
	if !ok {
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}, false
	}
	switch result {
	case hmacUsed:
		return &pond.Reply{Status: pond.Reply_HMAC_USED.Enum()}, false
	case hmacRevoked:
		return &pond.Reply{Status: pond.Reply_HMAC_REVOKED.Enum()}, false
	case hmacFresh:
		return nil, true
	default:
		panic("should not happen")
	}
}

// timeToFilenamePrefix returns a string that contains a hex encoding of t,
// accurate to the millisecond.
func timeToFilenamePrefix(t time.Time) string {
	return fmt.Sprintf("%016x", uint64(t.UnixNano()/1000000))
}

func (s *Server) deliver(from *[32]byte, del *pond.Delivery) *pond.Reply {
	var to [32]byte
	if len(del.To) != len(to) {
		return &pond.Reply{Status: pond.Reply_PARSE_ERROR.Enum()}
	}
	copy(to[:], del.To)

	if b := len(del.OneTimePublicKey) > 0; b != (del.HmacOfPublicKey != nil) || b != (len(del.OneTimeSignature) > 0) {
		return &pond.Reply{Status: pond.Reply_PARSE_ERROR.Enum()}
	}

	if (len(del.GroupSignature) > 0) != (del.Generation != nil) {
		return &pond.Reply{Status: pond.Reply_PARSE_ERROR.Enum()}
	}

	hmacAuthenticated := len(del.OneTimePublicKey) > 0
	groupSignatureAuthenticated := len(del.GroupSignature) > 0

	if hmacAuthenticated == groupSignatureAuthenticated {
		return &pond.Reply{Status: pond.Reply_PARSE_ERROR.Enum()}
	}

	account, ok := s.getAccount(&to)
	if !ok {
		return &pond.Reply{Status: pond.Reply_NO_SUCH_ADDRESS.Enum()}
	}

	switch {
	case groupSignatureAuthenticated:
		reply, ok := authenticateDeliveryWithGroupSignature(account, del)
		if !ok {
			return reply
		}
	case hmacAuthenticated:
		reply, ok := authenticateDeliveryWithHMAC(account, del)
		if !ok {
			return reply
		}
	default:
		panic("internal error")
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

	sha := sha256.New()
	sha.Write(del.Message)
	digest := sha.Sum(nil)

	msgPath := filepath.Join(path, timeToFilenamePrefix(time.Now())+fmt.Sprintf("%x", digest))
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

		var minName string
		names := make([]string, 0, len(ents))

		for _, ent := range ents {
			name := ent.Name()
			if strings.HasPrefix(name, announcePrefix) {
				isAnnounce = true
				minName = name
				break
			}
			if len(name) == (32+8)*2 && strings.IndexFunc(name, notLowercaseHex) == -1 {
				names = append(names, name)
			}
		}

		sort.Strings(names)
		if len(minName) == 0 && len(names) > 0 {
			minName = names[0]
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
		GroupSignature: del.GroupSignature,
		Generation:     del.Generation,
		Message:        del.Message,
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
	if group == nil {
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
	}
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

func (s *Server) hmacSetup(from *[32]byte, setup *pond.HMACSetup) *pond.Reply {
	account, ok := s.getAccount(from)
	if !ok {
		return &pond.Reply{Status: pond.Reply_NO_ACCOUNT.Enum()}
	}

	if len(setup.HmacKey) != len(account.hmacKey) {
		return &pond.Reply{Status: pond.Reply_PARSE_ERROR.Enum()}
	}

	existingHMACKey, ok := account.HMACKey()
	if ok {
		if subtle.ConstantTimeCompare(setup.HmacKey, existingHMACKey[:]) == 1 {
			return &pond.Reply{Status: pond.Reply_OK.Enum()}
		} else {
			return &pond.Reply{Status: pond.Reply_HMAC_KEY_ALREADY_SET.Enum()}
		}
	}

	if err := ioutil.WriteFile(account.HMACKeyPath(), setup.HmacKey, 0600); err != nil {
		log.Printf("failed to write HMAC key file: %s", err)
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
	}
	copy(account.hmacKey[:], setup.HmacKey)
	account.hmacKeyValid = true

	return nil
}

func (s *Server) hmacStrike(from *[32]byte, strike *pond.HMACStrike) *pond.Reply {
	account, ok := s.getAccount(from)
	if !ok {
		return &pond.Reply{Status: pond.Reply_NO_ACCOUNT.Enum()}
	}

	if !account.InsertHMACs(strike.Hmacs) {
		return &pond.Reply{Status: pond.Reply_INTERNAL_ERROR.Enum()}
	}

	return nil
}
