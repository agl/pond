package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	math_rand "math/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/salsa20"

	"github.com/agl/ed25519"
	"github.com/agl/pond/bbssig"
	pond "github.com/agl/pond/protos"
	"github.com/agl/pond/transport"
	"github.com/golang/protobuf/proto"
)

type TestServer struct {
	sync.WaitGroup

	listener       *net.TCPListener
	addr           *net.TCPAddr
	server         *Server
	dir            string
	identity       [32]byte
	identityPublic [32]byte
}

func (t *TestServer) Loop() {
	t.Add(1)
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			break
		}

		t.Add(1)
		go t.handleConnection(conn)
	}
	t.Done()
}

func (t *TestServer) handleConnection(rawConn net.Conn) {
	conn := transport.NewServer(rawConn, &t.identity)

	if err := conn.Handshake(); err != nil {
		panic(err)
	}

	t.server.Process(conn)
	conn.Close()
	t.Done()
}

func (t *TestServer) Dial(identity, identityPublic *[32]byte) *transport.Conn {
	rawConn, err := net.DialTCP("tcp", nil, t.addr)
	if err != nil {
		panic(err)
	}

	conn := transport.NewClient(rawConn, identity, identityPublic, &t.identityPublic)
	if err := conn.Handshake(); err != nil {
		panic(err)
	}
	return conn
}

func (t *TestServer) Close() {
	t.listener.Close()
	t.Wait()
}

func NewTestServer(setup func(dir string)) *TestServer {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		panic(err)
	}

	dir, err := ioutil.TempDir("", "servertest")
	if err != nil {
		panic(err)
	}

	if setup != nil {
		setup(dir)
	}

	testServer := &TestServer{
		listener: listener,
		addr:     listener.Addr().(*net.TCPAddr),
		dir:      dir,
		server:   NewServer(dir, true),
	}
	io.ReadFull(rand.Reader, testServer.identity[:])
	curve25519.ScalarBaseMult(&testServer.identityPublic, &testServer.identity)

	go testServer.Loop()
	return testServer
}

type script struct {
	numPlayers             int
	numPlayersWithAccounts int
	setupDir               func(dir string)
	actions                []action
}

type action struct {
	player          int
	buildRequest    func(*scriptState) *pond.Request
	request         *pond.Request
	payload         []byte
	validate        func(*testing.T, *pond.Reply)
	payloadSize     int
	validatePayload func(*testing.T, []byte)
	// noAck can be set to suppress reading the ACK byte from the server,
	// e.g. when simulating a truncated upload.
	noAck bool
}

type scriptState struct {
	identities       [][32]byte
	publicIdentities [][32]byte
	groupPrivateKeys []*bbssig.PrivateKey
	hmacKeys         [][32]byte
	testServer       *TestServer
}

func (s *scriptState) buildDelivery(to int, message []byte, generation uint32) *pond.Request {
	memberKey, err := s.groupPrivateKeys[to].NewMember(rand.Reader)
	if err != nil {
		panic(err)
	}
	sha := sha256.New()
	sha.Write(message)
	digest := sha.Sum(nil)

	sig, err := memberKey.Sign(rand.Reader, digest, sha)
	if err != nil {
		panic(err)
	}
	return &pond.Request{
		Deliver: &pond.Delivery{
			To:             s.publicIdentities[to][:],
			GroupSignature: sig,
			Generation:     proto.Uint32(generation),
			Message:        message,
		},
	}
}

type salsaRNG struct {
	seed int
}

func (rng salsaRNG) Read(buf []byte) (n int, err error) {
	for i := range buf {
		buf[i] = 0
	}

	var nonce [8]byte
	var key [32]byte
	binary.LittleEndian.PutUint32(key[:], uint32(rng.seed))
	rng.seed++
	salsa20.XORKeyStream(buf, buf, nonce[:], &key)

	return len(buf), nil
}

func (s *scriptState) makeOneTimePubKey(to int, seed int) (pub *[ed25519.PublicKeySize]byte, priv *[ed25519.PrivateKeySize]byte, digest uint64) {
	rng := rand.Reader
	if seed >= 0 {
		rng = &salsaRNG{seed}
	}
	pub, priv, err := ed25519.GenerateKey(rng)
	if err != nil {
		panic("ed25519 Generate Key failed: " + err.Error())
	}

	h := hmac.New(sha256.New, s.hmacKeys[to][:])
	h.Write(pub[:])
	digestFull := h.Sum(nil)
	digest = binary.LittleEndian.Uint64(digestFull) & hmacValueMask
	return
}

func (s *scriptState) buildHMACDelivery(to int, message []byte, seed int) *pond.Request {
	pub, priv, digest := s.makeOneTimePubKey(to, seed)
	sig := ed25519.Sign(priv, message)

	return &pond.Request{
		Deliver: &pond.Delivery{
			To:               s.publicIdentities[to][:],
			Message:          message,
			OneTimePublicKey: pub[:],
			HmacOfPublicKey:  proto.Uint64(digest),
			OneTimeSignature: sig[:],
		},
	}
}

func runScript(t *testing.T, s script) {
	server := NewTestServer(s.setupDir)
	defer server.Close()

	identities := make([][32]byte, s.numPlayers)
	publicIdentities := make([][32]byte, s.numPlayers)
	for i := range identities {
		io.ReadFull(rand.Reader, identities[i][:])
		curve25519.ScalarBaseMult(&publicIdentities[i], &identities[i])
	}

	groupPrivateKeys := make([]*bbssig.PrivateKey, s.numPlayersWithAccounts)
	hmacKeys := make([][32]byte, s.numPlayersWithAccounts)
	for i := range groupPrivateKeys {
		var err error
		groupPrivateKeys[i], err = bbssig.GenerateGroup(rand.Reader)
		if err != nil {
			panic(err)
		}
		rand.Reader.Read(hmacKeys[i][:])

		conn := server.Dial(&identities[i], &publicIdentities[i])
		if err := conn.WriteProto(&pond.Request{
			NewAccount: &pond.NewAccount{
				Generation: proto.Uint32(0),
				Group:      groupPrivateKeys[i].Group.Marshal(),
				HmacKey:    hmacKeys[i][:],
			},
		}); err != nil {
			t.Fatal(err)
		}

		reply := new(pond.Reply)
		if err := conn.ReadProto(reply); err != nil {
			t.Fatalf("Error while reading reply from server: %s", err)
		}
		if reply.AccountCreated == nil {
			t.Fatalf("Failed to create 1st account: %s", err)
		}
		conn.Close()
	}

	state := &scriptState{
		identities:       identities,
		publicIdentities: publicIdentities,
		groupPrivateKeys: groupPrivateKeys,
		hmacKeys:         hmacKeys,
		testServer:       server,
	}

	for _, a := range s.actions {
		conn := server.Dial(&identities[a.player], &publicIdentities[a.player])

		req := a.request
		if a.buildRequest != nil {
			req = a.buildRequest(state)
		}
		if err := conn.WriteProto(req); err != nil {
			t.Fatal(err)
		}

		reply := new(pond.Reply)
		if err := conn.ReadProto(reply); err != nil {
			t.Fatal(err)
		}
		if a.validate != nil {
			a.validate(t, reply)
		}

		if len(a.payload) > 0 {
			_, err := conn.Write(a.payload)
			if err != nil {
				t.Fatalf("Failed to write payload: %s", err)
			}
		}
		if a.payloadSize > 0 {
			fromServer := make([]byte, a.payloadSize)
			if _, err := io.ReadFull(conn, fromServer); err != nil {
				t.Errorf("Failed to read payload: %s", err)
			}
			if a.validatePayload != nil {
				a.validatePayload(t, fromServer)
			}
		}
		if len(a.payload) > 0 && !a.noAck {
			var ack [1]byte
			if n, err := conn.Read(ack[:]); err != nil || n != 1 {
				t.Fatalf("Failed to read ack: %d %s", n, err)
			}
		}
		conn.Close()
	}
}

func oneShotTest(t *testing.T, request *pond.Request, validate func(*testing.T, *pond.Reply)) {
	runScript(t, script{
		numPlayers: 1,
		actions: []action{
			{
				request:  request,
				validate: validate,
			},
		},
	})
}

func TestNoAccount(t *testing.T) {
	t.Parallel()

	oneShotTest(t, &pond.Request{Fetch: new(pond.Fetch)}, func(t *testing.T, reply *pond.Reply) {
		if reply.Status == nil || *reply.Status != pond.Reply_NO_ACCOUNT {
			t.Errorf("Bad reply when fetching from invalid account: %s", reply)
		}
	})
}

func TestNoRequest(t *testing.T) {
	t.Parallel()

	oneShotTest(t, &pond.Request{}, func(t *testing.T, reply *pond.Reply) {
		if reply.Status == nil || *reply.Status != pond.Reply_NO_REQUEST {
			t.Errorf("Bad reply with no request: %s", reply)
		}
	})
}

func TestInvalidAddress(t *testing.T) {
	t.Parallel()

	oneShotTest(t, &pond.Request{
		Deliver: &pond.Delivery{
			To:             make([]byte, 5),
			GroupSignature: make([]byte, 5),
			Generation:     proto.Uint32(0),
			Message:        make([]byte, 5),
		},
	}, func(t *testing.T, reply *pond.Reply) {
		if reply.Status == nil || *reply.Status != pond.Reply_PARSE_ERROR {
			t.Errorf("Bad reply to delivery with invalid address: %s", reply)
		}
	})
}

func TestNoSuchAddress(t *testing.T) {
	t.Parallel()

	oneShotTest(t, &pond.Request{
		Deliver: &pond.Delivery{
			To:             make([]byte, 32),
			GroupSignature: make([]byte, 5),
			Generation:     proto.Uint32(0),
			Message:        make([]byte, 5),
		},
	}, func(t *testing.T, reply *pond.Reply) {
		if reply.Status == nil || *reply.Status != pond.Reply_NO_SUCH_ADDRESS {
			t.Errorf("Bad reply to delivery with invalid address: %s", reply)
		}
	})
}

func TestBadNewAccount(t *testing.T) {
	t.Parallel()

	oneShotTest(t, &pond.Request{
		NewAccount: &pond.NewAccount{
			Generation: proto.Uint32(0),
			Group:      make([]byte, 5),
		},
	}, func(t *testing.T, reply *pond.Reply) {
		if reply.AccountCreated != nil {
			t.Errorf("Bad reply to new account: %s", reply)
		}
	})
}

func TestNewAccount(t *testing.T) {
	t.Parallel()

	groupPrivateKey, err := bbssig.GenerateGroup(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	oneShotTest(t, &pond.Request{
		NewAccount: &pond.NewAccount{
			Generation: proto.Uint32(0),
			Group:      groupPrivateKey.Group.Marshal(),
		},
	}, func(t *testing.T, reply *pond.Reply) {
		if reply.AccountCreated == nil {
			t.Errorf("Bad reply to new account: %s", reply)
		}
	})
}

func TestPingPong(t *testing.T) {
	t.Parallel()

	message0 := make([]byte, 1000)
	io.ReadFull(rand.Reader, message0)
	message1 := make([]byte, 1000)
	io.ReadFull(rand.Reader, message1)

	runScript(t, script{
		numPlayers:             2,
		numPlayersWithAccounts: 2,
		actions: []action{
			{
				player: 0,
				buildRequest: func(s *scriptState) *pond.Request {
					return s.buildDelivery(1, message1, 1)
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status != nil {
						t.Errorf("Bad reply to first message send: %s", reply)
					}
				},
			},
			{
				player: 1,
				buildRequest: func(s *scriptState) *pond.Request {
					return s.buildDelivery(0, message0, 1)
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status != nil {
						t.Errorf("Bad reply to second message send: %s", reply)
					}
				},
			},
			{
				player: 0,
				request: &pond.Request{
					Fetch: &pond.Fetch{},
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status != nil {
						t.Errorf("Bad reply to first fetch: %s", reply)
						return
					}
					if reply.Fetched == nil {
						t.Errorf("No fetch result: %s", reply)
						return
					}
					if !bytes.Equal(reply.Fetched.Message, message0) {
						t.Errorf("Corrupt message: %s", reply)
						return
					}
				},
			},
			{
				player: 0,
				request: &pond.Request{
					Fetch: &pond.Fetch{},
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status != nil {
						t.Errorf("Bad reply to second fetch: %s", reply)
						return
					}
					if reply.Fetched != nil {
						t.Errorf("Fetched message twice!: %s", reply)
						return
					}
				},
			},
		},
	})
}

func TestUpload(t *testing.T) {
	t.Parallel()

	payload := []byte("hello world")

	runScript(t, script{
		numPlayers:             2,
		numPlayersWithAccounts: 1,
		actions: []action{
			{
				player: 0,
				request: &pond.Request{
					Upload: &pond.Upload{
						Id:   proto.Uint64(1),
						Size: proto.Int64(int64(len(payload))),
					},
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status != nil {
						t.Fatalf("Bad reply to upload: %s", reply)
					}
					if reply.Upload == nil {
						t.Fatalf("Upload reply missing: %s", reply)
					}
					if reply.Upload.Resume != nil {
						t.Fatalf("Upload reply contained unexpected Resume: %s", reply)
					}
				},
				payload: payload,
			},
			{
				player: 1,
				buildRequest: func(s *scriptState) *pond.Request {
					return &pond.Request{
						Download: &pond.Download{
							From: s.publicIdentities[0][:],
							Id:   proto.Uint64(1),
						},
					}
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status != nil {
						t.Fatalf("Bad reply to download: %s", reply)
					}
					if reply.Download == nil {
						t.Fatalf("Download reply missing: %s", reply)
					}
					if *reply.Download.Size != int64(len(payload)) {
						t.Fatalf("Download reply contained wrong size: %d vs %d", *reply.Download.Size, len(payload))
					}
				},
				payloadSize: len(payload),
				validatePayload: func(t *testing.T, fromServer []byte) {
					if !bytes.Equal(payload, fromServer) {
						t.Errorf("bad payload in download: %x", fromServer)
					}
				},
			},
		},
	})
}

func TestOversizeUpload(t *testing.T) {
	t.Parallel()

	runScript(t, script{
		numPlayers:             1,
		numPlayersWithAccounts: 1,
		actions: []action{
			{
				player: 0,
				request: &pond.Request{
					Upload: &pond.Upload{
						Id:   proto.Uint64(1),
						Size: proto.Int64(1 << 27),
					},
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status == nil || *reply.Status != pond.Reply_OVER_QUOTA {
						t.Fatalf("Bad reply to upload: %s", reply)
					}
				},
			},
		},
	})
}

func TestQuotaOverride(t *testing.T) {
	t.Parallel()

	runScript(t, script{
		numPlayers:             1,
		numPlayersWithAccounts: 1,
		actions: []action{
			{
				player: 0,
				buildRequest: func(s *scriptState) *pond.Request {
					path := filepath.Join(s.testServer.dir, "accounts", fmt.Sprintf("%x", s.publicIdentities[0][:]), "quota-megabytes")
					ioutil.WriteFile(path, []byte("200\n"), 0644)

					return &pond.Request{
						Upload: &pond.Upload{
							Id:   proto.Uint64(1),
							Size: proto.Int64(1 << 27),
						},
					}
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status != nil {
						t.Errorf("Bad reply to upload: %s", reply)
						return
					}
					if reply.Upload == nil {
						t.Errorf("Upload reply missing: %s", reply)
						return
					}
					if reply.Upload.Resume != nil {
						t.Errorf("Upload reply contained unexpected Resume: %s", reply)
						return
					}
				},
			},
		},
	})
}

func TestResumeUpload(t *testing.T) {
	t.Parallel()

	payload := []byte("hello world")

	runScript(t, script{
		numPlayers:             2,
		numPlayersWithAccounts: 1,
		actions: []action{
			{
				player: 0,
				request: &pond.Request{
					Upload: &pond.Upload{
						Id:   proto.Uint64(1),
						Size: proto.Int64(int64(len(payload))),
					},
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status != nil {
						t.Fatalf("Bad reply to upload: %s", reply)
					}
					if reply.Upload == nil {
						t.Fatalf("Upload reply missing: %s", reply)
					}
					if reply.Upload.Resume != nil {
						t.Fatalf("Upload reply contained unexpected Resume: %s", reply)
					}
				},
				payload: payload[:2],
				// Warning: this is inheriently racy. We don't
				// wait for the ack from the server (because
				// one will never come because we don't
				// complete the upload). However, we don't know
				// that the server has finished processing the
				// bytes that we did send it.
				noAck: true,
			},
			{
				player: 0,
				request: &pond.Request{
					Upload: &pond.Upload{
						Id:   proto.Uint64(1),
						Size: proto.Int64(int64(len(payload))),
					},
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status != nil {
						t.Fatalf("Bad reply to upload: %s", reply)
					}
					if reply.Upload == nil {
						t.Fatalf("Upload reply missing: %s", reply)
					}
					if reply.Upload.Resume == nil || *reply.Upload.Resume != 2 {
						t.Fatalf("Upload reply contained unexpected Resume: %s", reply)
					}
				},
				payload: payload[2:],
			},
			{
				player: 1,
				buildRequest: func(s *scriptState) *pond.Request {
					return &pond.Request{
						Download: &pond.Download{
							From: s.publicIdentities[0][:],
							Id:   proto.Uint64(1),
						},
					}
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status != nil {
						t.Fatalf("Bad reply to download: %s", reply)
					}
					if reply.Download == nil {
						t.Fatalf("Download reply missing: %s", reply)
					}
					if *reply.Download.Size != int64(len(payload)) {
						t.Fatalf("Download reply contained wrong size: %d vs %d", *reply.Download.Size, len(payload))
					}
				},
				payloadSize: len(payload),
				validatePayload: func(t *testing.T, fromServer []byte) {
					if !bytes.Equal(payload, fromServer) {
						t.Errorf("bad payload in download: %x", fromServer)
					}
				},
			},
		},
	})
}

func TestResumeDownload(t *testing.T) {
	t.Parallel()

	payload := []byte("hello world")

	runScript(t, script{
		numPlayers:             2,
		numPlayersWithAccounts: 1,
		actions: []action{
			{
				player: 0,
				request: &pond.Request{
					Upload: &pond.Upload{
						Id:   proto.Uint64(1),
						Size: proto.Int64(int64(len(payload))),
					},
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status != nil {
						t.Fatalf("Bad reply to upload: %s", reply)
					}
					if reply.Upload == nil {
						t.Fatalf("Upload reply missing: %s", reply)
					}
					if reply.Upload.Resume != nil {
						t.Fatalf("Upload reply contained unexpected Resume: %s", reply)
					}
				},
				payload: payload,
			},
			{
				player: 1,
				buildRequest: func(s *scriptState) *pond.Request {
					return &pond.Request{
						Download: &pond.Download{
							From:   s.publicIdentities[0][:],
							Id:     proto.Uint64(1),
							Resume: proto.Int64(2),
						},
					}
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status != nil {
						t.Fatalf("Bad reply to download: %s", reply)
					}
					if reply.Download == nil {
						t.Fatalf("Download reply missing: %s", reply)
					}
					if *reply.Download.Size != int64(len(payload)) {
						t.Fatalf("Download reply contained wrong size: %d vs %d", *reply.Download.Size, len(payload))
					}
				},
				payloadSize: len(payload) - 2,
				validatePayload: func(t *testing.T, fromServer []byte) {
					if !bytes.Equal(payload[2:], fromServer) {
						t.Errorf("bad payload in download: %x", fromServer)
					}
				},
			},
			{
				player: 1,
				buildRequest: func(s *scriptState) *pond.Request {
					return &pond.Request{
						Download: &pond.Download{
							From:   s.publicIdentities[0][:],
							Id:     proto.Uint64(1),
							Resume: proto.Int64(20),
						},
					}
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status == nil || *reply.Status != pond.Reply_RESUME_PAST_END_OF_FILE {
						t.Fatalf("Bad reply to download: %s", reply)
					}
				},
			},
		},
	})
}

func TestAnnounce(t *testing.T) {
	t.Parallel()

	runScript(t, script{
		numPlayers:             1,
		numPlayersWithAccounts: 1,
		actions: []action{
			{
				player: 0,
				buildRequest: func(state *scriptState) *pond.Request {
					announce := &pond.Message{
						Id:       proto.Uint64(0),
						Time:     proto.Int64(time.Now().Unix()),
						Body:     []byte("Hello world"),
						MyNextDh: []byte{},
					}
					announceBytes, err := proto.Marshal(announce)
					t.Logf("%x", announceBytes)
					if err != nil {
						t.Fatalf("Failed to marshal announce message: %s", err)
					}
					if err = ioutil.WriteFile(fmt.Sprintf("%s/accounts/%x/announce-00000000", state.testServer.dir, state.publicIdentities[0]), announceBytes, 0666); err != nil {
						t.Fatalf("Failed to write announce message: %s", err)
					}
					return &pond.Request{
						Fetch: &pond.Fetch{},
					}
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status != nil {
						t.Fatalf("Bad reply to upload: %s", reply)
					}
					if reply.Announce == nil {
						t.Fatalf("Announce reply missing: %s", reply)
					}
				},
			},
		},
	})
}

func TestSweep(t *testing.T) {
	t.Parallel()

	var fileDir, oldPath, newPath string

	runScript(t, script{
		numPlayers: 1,
		setupDir: func(dir string) {
			fileDir = filepath.Join(dir, "accounts", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "files")
			if err := os.MkdirAll(fileDir, 0700); err != nil {
				t.Fatalf("Failed to create files directory: %s", err)
			}

			oldPath = filepath.Join(fileDir, "01")
			file, err := os.Create(oldPath)
			if err != nil {
				t.Fatalf("Failed to create file: %s", err)
			}
			file.Close()
			oldTime := time.Now().AddDate(0, -2, 0)
			if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
				t.Fatalf("Failed to set times for old file: %s", err)
			}

			newPath = filepath.Join(fileDir, "02")
			file, err = os.Create(newPath)
			if err != nil {
				t.Fatalf("Failed to create file: %s", err)
			}
			file.Close()
		},
		actions: []action{
			{
				request: &pond.Request{},
			},
		},
	})

	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Errorf("old path was not removed: %s", err)
	}

	if _, err := os.Stat(newPath); err != nil {
		t.Errorf("new path was removed: %s", err)
	}
}

func TestRevocation(t *testing.T) {
	t.Parallel()

	message := []byte{1, 2, 3}
	var revocation *bbssig.Revocation

	runScript(t, script{
		numPlayers:             2,
		numPlayersWithAccounts: 1,
		actions: []action{
			{
				player: 0,
				buildRequest: func(s *scriptState) *pond.Request {
					memberKey, err := s.groupPrivateKeys[0].NewMember(rand.Reader)
					if err != nil {
						t.Errorf("Failed to create group member key: %s", err)
					}
					revocation = s.groupPrivateKeys[0].GenerateRevocation(memberKey)
					return &pond.Request{
						Revocation: &pond.SignedRevocation{
							Revocation: &pond.SignedRevocation_Revocation{
								Generation: proto.Uint32(0x1234),
								Revocation: revocation.Marshal(),
							},
							Signature: []byte{7, 8, 9},
						},
					}
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status != nil {
						t.Errorf("Bad reply to revocation: %s", reply)
					}
				},
			},
			{
				player: 1,
				buildRequest: func(s *scriptState) *pond.Request {
					return s.buildDelivery(0, message, 0x1234)
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status == nil || *reply.Status != pond.Reply_GENERATION_REVOKED {
						t.Errorf("Bad status to delivery request: %#v", reply)
					}
					if reply.Revocation == nil {
						t.Errorf("Missing revocation information: %#v", reply)
					}
				},
			},
			{
				player: 1,
				buildRequest: func(s *scriptState) *pond.Request {
					s.groupPrivateKeys[0].Update(revocation)
					return s.buildDelivery(0, message, 0x1235)
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status != nil {
						t.Errorf("Bad reply to revocation: %s", reply)
					}
				},
			},
		},
	})
}

func TestDoubleDelivery(t *testing.T) {
	t.Parallel()

	message := []byte{1, 2, 3}

	runScript(t, script{
		numPlayers:             2,
		numPlayersWithAccounts: 1,
		actions: []action{
			{
				player: 1,
				buildRequest: func(s *scriptState) *pond.Request {
					return s.buildHMACDelivery(0, message, 0)
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status != nil {
						t.Errorf("Bad reply to first message send: %s", reply)
					}
				},
			},
			{
				player: 1,
				buildRequest: func(s *scriptState) *pond.Request {
					return s.buildHMACDelivery(0, message, 0)
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status == nil || *reply.Status != pond.Reply_HMAC_USED {
						t.Errorf("Bad reply to duplicate message send: %s", reply)
					}
				},
			},
		},
	})
}

func TestDeliveryAfterRevocation(t *testing.T) {
	t.Parallel()

	message := []byte{1, 2, 3}

	runScript(t, script{
		numPlayers:             2,
		numPlayersWithAccounts: 1,
		actions: []action{
			{
				player: 0,
				buildRequest: func(s *scriptState) *pond.Request {
					_, _, hmac := s.makeOneTimePubKey(0, 0)
					return &pond.Request{
						HmacStrike: &pond.HMACStrike{
							Hmacs: []uint64{hmac | 1<<63},
						},
					}
				},
			},
			{
				player: 1,
				buildRequest: func(s *scriptState) *pond.Request {
					return s.buildHMACDelivery(0, message, 0)
				},
				validate: func(t *testing.T, reply *pond.Reply) {
					if reply.Status == nil || *reply.Status != pond.Reply_HMAC_REVOKED {
						t.Errorf("Bad reply to duplicate message send: %s", reply)
					}
				},
			},
		},
	})
}

func TestHMACInsertion(t *testing.T) {
	dir, err := ioutil.TempDir("", "hmactest")
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "hmacstrike")
	values := math_rand.Perm(1024)

	for i, v := range values {
		v64 := uint64(v)
		if i%2 == 0 {
			v64 |= 1 << 63
		}
		result, ok := insertHMAC(path, v64)
		if !ok {
			t.Fatal("insert failed")
		}
		if result != hmacFresh {
			t.Fatal("fresh value not recognised as such")
		}
	}

	for i, v := range values {
		result, ok := insertHMAC(path, uint64(v))
		if !ok {
			t.Fatal("insert failed")
		}
		expected := hmacUsed
		if i%2 == 0 {
			expected = hmacRevoked
		}
		if result != expected {
			t.Fatal("value double inserted")
		}
	}

	values = math_rand.Perm(2048)
	var valueBatch [16]uint64
	for i := 0; i < len(values); i += 16 {
		for i, v := range values[i : i+16] {
			valueBatch[i] = uint64(v)
			if i%2 == 1 {
				valueBatch[i] |= 1 << 63
			}
		}
		if !insertHMACs(path, valueBatch[:]) {
			t.Fatal("inserts failed")
		}
	}

	for _, v := range values {
		result, ok := insertHMAC(path, uint64(v))
		if !ok {
			t.Fatal("insert failed")
		}
		if result == hmacFresh {
			t.Fatalf("value double inserted")
		}
	}
}
