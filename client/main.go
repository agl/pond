package main

import (
	"crypto/rand"
	"os"
	"runtime"
)

func main() {
	if os.Getenv("POND") != "experimental" {
		println("Pond is experimental software and not intended for general use!")
		os.Exit(1)
	}

	runtime.GOMAXPROCS(4)

	ui := NewGTKUI()
	NewClient("state", ui, rand.Reader, false)
	ui.Run()
}
