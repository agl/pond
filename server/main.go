package main

import (
	"crypto/rand"
	"encoding/base32"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/curve25519"

	pond "github.com/agl/pond/protos"
	"github.com/agl/pond/server/protos"
	"github.com/agl/pond/transport"
)

var (
	baseDirectory *string = flag.String("base-directory", "", "directory to store server state and config")
	initFlag      *bool   = flag.Bool("init", false, "if true, setup a new base directory")
	port          *int    = flag.Int("port", 16333, "TCP port to use when setting up a new base directory")
	makeAnnounce  *string = flag.String("make-announce", "", "If set, the location of a text file containing an announcement message which will be written to stdout in binary.")
	lifelineFd    *int    = flag.Int("lifeline-fd", -1, "If set, the server will exit when this descriptor returns EOF")
)

const configFilename = "config"
const identityFilename = "identity"

func main() {
	flag.Parse()

	if len(*makeAnnounce) > 0 {
		msgBytes, err := ioutil.ReadFile(*makeAnnounce)
		if err != nil {
			panic(err)
		}
		announce := &pond.Message{
			Id:           proto.Uint64(0),
			Time:         proto.Int64(time.Now().Unix()),
			Body:         msgBytes,
			MyNextDh:     []byte{},
			BodyEncoding: pond.Message_RAW.Enum(),
		}
		announceBytes, err := proto.Marshal(announce)
		if err != nil {
			panic(err)
		}
		os.Stdout.Write(announceBytes)
		return
	}

	if len(*baseDirectory) == 0 {
		log.Fatalf("Must give --base-directory")
		return
	}
	configPath := filepath.Join(*baseDirectory, configFilename)

	var identity [32]byte
	if *initFlag {
		if err := os.MkdirAll(*baseDirectory, 0700); err != nil {
			log.Fatalf("Failed to create base directory: %s", err)
			return
		}

		if _, err := io.ReadFull(rand.Reader, identity[:]); err != nil {
			log.Fatalf("Failed to read random bytes: %s", err)
			return
		}

		if err := ioutil.WriteFile(filepath.Join(*baseDirectory, identityFilename), identity[:], 0600); err != nil {
			log.Fatalf("Failed to write identity file: %s", err)
			return
		}

		defaultConfig := &protos.Config{
			Port: proto.Uint32(uint32(*port)),
		}

		configFile, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Fatalf("Failed to create config file: %s", err)
		}
		proto.MarshalText(configFile, defaultConfig)
		configFile.Close()
	}

	identityBytes, err := ioutil.ReadFile(filepath.Join(*baseDirectory, identityFilename))
	if err != nil {
		log.Print("Use --init to setup a new base directory")
		log.Fatalf("Failed to read identity file: %s", err)
		return
	}
	if len(identityBytes) != 32 {
		log.Fatalf("Identity file is not 32 bytes long")
		return
	}
	copy(identity[:], identityBytes)

	config := new(protos.Config)
	configBytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatalf("No config file found")
	}

	if err := proto.UnmarshalText(string(configBytes), config); err != nil {
		log.Fatalf("Failed to parse config: %s", err)
	}

	if err := maybeConvertMessagesToNewFormat(*baseDirectory); err != nil {
		log.Fatalf("Failed to convert messages to new naming scheme: %s", err)
	}

	ip := net.IPv4(127, 0, 0, 1) // IPv4 loopback interface

	if config.Address != nil {
		if ip = net.ParseIP(*config.Address); ip == nil {
			log.Fatalf("Failed to parse address from config: %s", ip)
		}
	}

	listenAddr := net.TCPAddr{
		IP:   ip,
		Port: int(*config.Port),
	}
	listener, err := net.ListenTCP("tcp", &listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on port: %s", err)
	}

	var identityPublic [32]byte
	curve25519.ScalarBaseMult(&identityPublic, &identity)
	identityString := strings.Replace(base32.StdEncoding.EncodeToString(identityPublic[:]), "=", "", -1)
	log.Printf("Started. Listening on port %d with identity %s", listener.Addr().(*net.TCPAddr).Port, identityString)

	server := NewServer(*baseDirectory, config.GetAllowRegistration())

	if *lifelineFd > -1 {
		lifeline := os.NewFile(uintptr(*lifelineFd), "lifeline")
		go func() {
			var buf [1]byte
			lifeline.Read(buf[:])
			os.Exit(255)
		}()
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %s", err)
			continue
		}

		go handleConnection(server, conn, &identity)
	}
}

func handleConnection(server *Server, rawConn net.Conn, identity *[32]byte) {
	rawConn.SetDeadline(time.Now().Add(30 * time.Second))
	conn := transport.NewServer(rawConn, identity)

	if err := conn.Handshake(); err != nil {
		log.Printf("Error from handshake: %s", err)
		return
	}

	server.Process(conn)
	conn.Close()
}

// maybeConvertMessagesToNewFormat scans the accounts directory for messages
// under the old naming scheme and updates them to use the new
// naming scheme that includes millisecond delivery time at the beginning.
func maybeConvertMessagesToNewFormat(baseDirectory string) error {
	accountsPath := filepath.Join(baseDirectory, "accounts")
	accountsDir, err := os.Open(accountsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer accountsDir.Close()

	accounts, err := accountsDir.Readdir(0)
	if err != nil {
		return err
	}

	for _, ent := range accounts {
		account := ent.Name()
		if len(account) != 64 || strings.IndexFunc(account, notLowercaseHex) != -1 {
			continue
		}

		accountPath := filepath.Join(accountsPath, account)
		accountDir, err := os.Open(accountPath)
		if err != nil {
			return err
		}
		ents, err := accountDir.Readdir(0)
		accountDir.Close()
		if err != nil {
			return err
		}

		for _, ent := range ents {
			name := ent.Name()
			if len(name) != 64 || strings.IndexFunc(name, notLowercaseHex) != -1 {
				continue
			}

			oldName := filepath.Join(accountPath, name)
			newName := filepath.Join(accountPath, timeToFilenamePrefix(ent.ModTime())+name)
			if err := os.Rename(oldName, newName); err != nil {
				return err
			}
		}
	}

	return nil
}
