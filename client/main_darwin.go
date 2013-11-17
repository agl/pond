package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/agl/pond/client/system"
)

func main() {
	devFlag := flag.Bool("dev", false, "Is this a development environment?")
	stateFile := flag.String("state-file", "", "File in which to save persistent state")
	flag.Parse()

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

	exePath := system.GetExecutablePath()
	if strings.HasSuffix(exePath, "Pond") {
		exeDir := filepath.Dir(exePath)
		os.Setenv("GDK_PIXBUF_MODULE_FILE", filepath.Join(exeDir, "../Resources/gdk-pixbuf/loaders.cache"))
		os.Setenv("GDK_PIXBUF_MODULEDIR", filepath.Join(exeDir, "../F"))
		os.Setenv("PANGO_SYSCONFDIR", filepath.Join(exeDir, "../Resources/etc"))
		os.Setenv("PANGO_LIBDIR", filepath.Join(exeDir, "../Resources/lib"))
		os.Chdir(exeDir)
	}

	ui := NewGTKUI()
	client := NewGUIClient(*stateFile, ui, rand.Reader, false /* testing */, true /* autoFetch */)
	client.dev = dev
	client.Start()
	ui.Run()
}
