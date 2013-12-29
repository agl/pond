package system

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// OS X doesn't appear to have a tmpfs mounted by default. However, it does
// appear to use encrypted swap by default, which is good. (Try running `sysctl
// vm.swapusage` to check.) So this function mounts a RAM-disk volume and
// unmounts it on exit (assuming that we don't crash). It would be nice if we
// could open a file descriptor to the directory and then lazy unmount it.
// However, Darwin doesn't appear to have lazy unmount, nor openat().

// IsSafe checks to see whether the current OS appears to be safe. Specifically
// it checks that any swap is encrypted.
func IsSafe() error {
	sysctlOutput, err := exec.Command("sysctl", "vm.swapusage").CombinedOutput()
	if err != nil {
		return errors.New("system: error when executing sysctl vm.swapusage: " + err.Error())
	}
	if !bytes.Contains(sysctlOutput, []byte("(encrypted)")) {
		return errors.New("swap does not appear to be encrypted")
	}
	return nil
}

var (
	// safeTempDir contains the name of a directory that is a RAM disk
	// mount once setupSafeTempDir has been run, unless safeTempDirErr is
	// non-nil.
	safeTempDir string
	// safeTempDirErr contains any errors arising from trying to setup a
	// RAM disk by setupSafeTempDir.
	safeTempDirErr error
	// safeTempDevice, if not empty, contains the device name of the RAM
	// disk created by setupSafeTempDir.
	safeTempDevice string
	// safeTempMounted is true if setupSafeTempDir mounted safeTempDevice
	// on /Volumes/$safeTempVolumeName.
	safeTempMounted bool
	// safeTempDirOnce protects setupSafeTempDir from running multiple
	// times.
	safeTempDirOnce sync.Once
	// safeTempVolumName contains the name of the RAM disk volume that
	// we'll create. This turns into a directory name in /Volumes and also
	// appears in the Disk Utility GUI when Pond is running.
	safeTempVolumeName string
)

func setupSafeTempDir() {
	var randBytes [6]byte
	rand.Reader.Read(randBytes[:])
	safeTempVolumeName = fmt.Sprintf("Pond RAM disk (%x)", randBytes)

	hdiUtilOutput, err := exec.Command("hdiutil", "attach", "-nomount", "ram://2048").CombinedOutput()
	if err != nil {
		safeTempDirErr = err
		return
	}
	device := strings.TrimSpace(string(hdiUtilOutput))
	safeTempDevice = device
	if err := exec.Command("diskutil", "erasevolume", "HFS+", safeTempVolumeName, device).Run(); err != nil {
		safeTempDirErr = err
		return
	}

	safeTempMounted = true
	safeTempDir = "/Volumes/" + safeTempVolumeName

	readMe, err := os.OpenFile(filepath.Join(safeTempDir, "README"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		safeTempDirErr = err
		return
	}
	defer readMe.Close()

	fmt.Fprintf(readMe, `Pond Safe Temp Directory

This directory contains a RAM filesystem, created by Pond, so that temporary files
can be safely used. Unless Pond is still running, it has somehow failed to cleanup
after itself! Sorry! You can run the following commands to clean it up:

$ cd ~
$ umount "/Volumes/%s"
$ hdiutil detach %s
`, safeTempVolumeName, device)
}

func SafeTempDir() (string, error) {
	safeTempDirOnce.Do(setupSafeTempDir)
	if safeTempDirErr != nil {
		return "", safeTempDirErr
	}
	return safeTempDir, nil
}

// runCommandWithIOOnError runs a command and sends the output to Stdout in the
// even of an error.
func runCommandWithIOOnError(name string, args ...string) error {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err == nil {
		return nil
	}
	fmt.Printf("Failed to run command: %s %s: %s", name, strings.Join(args, " "), err)
	os.Stdout.Write(output)
	return err
}

// Shutdown performs any needed cleanup and should be called by a defer in
// main().
func Shutdown() {
	if safeTempMounted {
		runCommandWithIOOnError("umount", "/Volumes/"+safeTempVolumeName)
		safeTempMounted = false
	}
	if len(safeTempDevice) > 0 {
		runCommandWithIOOnError("hdiutil", "detach", safeTempDevice)
		safeTempDevice = ""
	}
}
