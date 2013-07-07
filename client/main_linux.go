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
	dev := os.Getenv("POND") == "dev"
	runtime.GOMAXPROCS(4)
	flag.Parse()

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

	ui := NewGTKUI()
	client := NewClient(*stateFile, ui, rand.Reader, false /* testing */, true /* autoFetch */)
	client.dev = dev
	client.Start()
	ui.Run()
}
