package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func main() {
	devFlag := flag.Bool("dev", false, "Is this a development environment?")
	stateFile := flag.String("state-file", "", "File in which to save persistent state")
	flag.Parse()

	runtime.LockOSThread()

	dev := os.Getenv("POND") == "dev" || *devFlag
	runtime.GOMAXPROCS(4)

	if len(*stateFile) == 0 && dev {
		*stateFile = "state"
	}

	if len(*stateFile) == 0 {
		home := os.Getenv("HOME")
		if len(home) == 0 {
			fmt.Fprintf(os.Stderr, "$HOME not set. Please export $HOME to set the directory for the state file.\n")
			os.Exit(1)
		}
		*stateFile = filepath.Join(home, ".pond")
	}

	ui := NewGTKUI()
	client := NewGUIClient(*stateFile, ui, rand.Reader, false /* testing */, true /* autoFetch */)
	client.dev = dev
	client.Start()
	ui.Run()
}
