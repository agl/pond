package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

var stateFile *string = flag.String("state-file", "", "File in which to save persistent state")

func main() {
	devFlag := flag.Bool("dev", false, "Is this a development environment?")
	flag.Parse()

	dev := os.Getenv("POND") == "dev" || *devFlag
	runtime.GOMAXPROCS(4)

	if len(*stateFile) == 0 && dev {
		*stateFile = "state"
	}

	if len(*stateFile) == 0 {
		home := os.Getenv("HOME")
		if len(home) == 0 {
			fmt.Fprintf(os.Stderr, "$HOME not set. Please either export $HOME or use --state-file to set the location of the state file explicitly.\n")
			os.Exit(1)
		}
		configDir := filepath.Join(home, ".config")
		os.Mkdir(configDir, 0700)
		*stateFile = filepath.Join(configDir, "pond")
	}

	if len(os.Getenv("PONDCLI")) > 0 {
		client := NewCLIClient(*stateFile, rand.Reader, false /* testing */, true /* autoFetch */)
		client.dev = dev
		client.Start()
	} else {
		ui := NewGTKUI()
		client := NewGUIClient(*stateFile, ui, rand.Reader, false /* testing */, true /* autoFetch */)
		client.dev = dev
		client.Start()
		ui.Run()
	}
}
