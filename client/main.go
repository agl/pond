package main

import (
	"crypto/rand"
	"flag"
	"os"
	"runtime"
)

var stateFile *string = flag.String("state-file", "state", "File in which to save persistent state")

func main() {
	testing := false

	switch os.Getenv("POND") {
	case "dev":
		testing = true
	case "experimental":
		break
	default:
		println("Pond is experimental software and not intended for general use!")
		os.Exit(1)
	}
	runtime.GOMAXPROCS(4)
	flag.Parse()

	ui := NewGTKUI()
	client := NewClient(*stateFile, ui, rand.Reader, testing, true /* autoFetch */)
	client.Start()
	ui.Run()
}
