package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"testing"
	"time"

	"code.google.com/p/go.crypto/curve25519"

	"code.google.com/p/goprotobuf/proto"
	"github.com/agl/pond/bbssig"
	pond "github.com/agl/pond/protos"
	"github.com/agl/pond/transport"
)

type TestServer struct {
	listener       *net.TCPListener
	addr           *net.TCPAddr
	server         *Server
	dir            string
	identity       [32]byte
	identityPublic [32]byte
}

func (t *TestServer) Loop() {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			break
		}

		go t.handleConnection(conn)
	}
}

func (t *TestServer) handleConnection(rawConn net.Conn) {
	conn := transport.NewServer(rawConn, &t.identity)

	if err := conn.Handshake(); err != nil {
		panic(err)
	}

	t.server.Process(conn)
	conn.Close()
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
}

func NewTestServer() *TestServer {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		panic(err)
	}

	dir, err := ioutil.TempDir("", "servertest")
	if err != nil {
		panic(err)
	}

	testServer := &TestServer{
		listener: listener,
		addr:     listener.Addr().(*net.TCPAddr),
		dir:      dir,
		server:   NewServer(dir),
	}
	io.ReadFull(rand.Reader, testServer.identity[:])
	curve25519.ScalarBaseMult(&testServer.identityPublic, &testServer.identity)

	go testServer.Loop()
	return testServer
}

type script struct {
	numPlayers             int
	numPlayersWithAccounts int
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
}

type scriptState struct {
	identities       [][32]byte
	publicIdentities [][32]byte
	groupPrivateKeys []*bbssig.PrivateKey
	testServer       *TestServer
}

func (s *scriptState) buildDelivery(to int, message []byte) *pond.Request {
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
			To:         s.publicIdentities[to][:],
			Signature:  sig,
			Generation: proto.Uint32(0),
			Message:    message,
		},
	}
}

func runScript(t *testing.T, s script) {
	server := NewTestServer()
	defer server.Close()

	identities := make([][32]byte, s.numPlayers)
	publicIdentities := make([][32]byte, s.numPlayers)
	for i := range identities {
		io.ReadFull(rand.Reader, identities[i][:])
		curve25519.ScalarBaseMult(&publicIdentities[i], &identities[i])
	}

	groupPrivateKeys := make([]*bbssig.PrivateKey, s.numPlayersWithAccounts)
	for i := range groupPrivateKeys {
		var err error
		groupPrivateKeys[i], err = bbssig.GenerateGroup(rand.Reader)
		if err != nil {
			panic(err)
		}

		conn := server.Dial(&identities[i], &publicIdentities[i])
		if err := conn.WriteProto(&pond.Request{
			NewAccount: &pond.NewAccount{
				Generation: proto.Uint32(0),
				Group:      groupPrivateKeys[i].Group.Marshal(),
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
		a.validate(t, reply)

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
	oneShotTest(t, &pond.Request{Fetch: new(pond.Fetch)}, func(t *testing.T, reply *pond.Reply) {
		if reply.Status == nil || *reply.Status != pond.Reply_NO_ACCOUNT {
			t.Errorf("Bad reply when fetching from invalid account: %s", reply)
		}
	})
}

func TestNoRequest(t *testing.T) {
	oneShotTest(t, &pond.Request{}, func(t *testing.T, reply *pond.Reply) {
		if reply.Status == nil || *reply.Status != pond.Reply_NO_REQUEST {
			t.Errorf("Bad reply with no request: %s", reply)
		}
	})
}

func TestInvalidAddress(t *testing.T) {
	oneShotTest(t, &pond.Request{
		Deliver: &pond.Delivery{
			To:         make([]byte, 5),
			Signature:  make([]byte, 5),
			Generation: proto.Uint32(0),
			Message:    make([]byte, 5),
		},
	}, func(t *testing.T, reply *pond.Reply) {
		if reply.Status == nil || *reply.Status != pond.Reply_PARSE_ERROR {
			t.Errorf("Bad reply to delivery with invalid address: %s", reply)
		}
	})
}

func TestNoSuchAddress(t *testing.T) {
	oneShotTest(t, &pond.Request{
		Deliver: &pond.Delivery{
			To:         make([]byte, 32),
			Signature:  make([]byte, 5),
			Generation: proto.Uint32(0),
			Message:    make([]byte, 5),
		},
	}, func(t *testing.T, reply *pond.Reply) {
		if reply.Status == nil || *reply.Status != pond.Reply_NO_SUCH_ADDRESS {
			t.Errorf("Bad reply to delivery with invalid address: %s", reply)
		}
	})
}

func TestBadNewAccount(t *testing.T) {
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
					return s.buildDelivery(1, message1)
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
					return s.buildDelivery(0, message0)
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
	runScript(t, script{
		numPlayers:             1,
		numPlayersWithAccounts: 1,
		actions: []action{
			{
				player: 0,
				request: &pond.Request{
					Upload: &pond.Upload{
						Id:   proto.Uint64(1),
						Size: proto.Int64(1 << 32),
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

func TestResumeUpload(t *testing.T) {
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
