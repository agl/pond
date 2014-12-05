package system

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

// IsSafe checks to see whether the current OS appears to be safe. Specifically
// it checks that any swap is encrypted.
func IsSafe() error {
	output, err := exec.Command("sysctl", "vm.swapencrypt.enable").Output()
	if err != nil {
		return errors.New("system: error when executing 'sysctl vm.swapencrypt.enable': " +
			err.Error())
	}
	if strings.TrimRight(string(output), "\n") != "vm.swapencrypt.enable=1" {
		return errors.New("system: swapping is not encrypted")
	}

	return nil
}

func stringFromInt8(s []int8) string {
	b := make([]byte, 0, len(s))

	for _, v := range s {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}

	return string(b)
}

func processFilesystems(f func(fstype, path string) error) error {
	n, err := syscall.Getfsstat(nil, 1 /* MNT_WAIT */)
	if err != nil {
		return errors.New("system: getfsstat error: " + err.Error())
	}

	filesystems := make([]syscall.Statfs_t, n)
	n, err = syscall.Getfsstat(filesystems, 1 /* MNT_WAIT */)
	if err != nil {
		return errors.New("system: Getfsstat error: " + err.Error())
	}

	for _, fs := range filesystems[:n] {
		fstype := stringFromInt8(fs.F_fstypename[:])
		path := stringFromInt8(fs.F_mntonname[:])
		if err := f(fstype, path); err != nil {
			return err
		}
	}

	return nil
}

var (
	safeTempDir     string
	safeTempDirErr  error
	safeTempDirOnce sync.Once
)

func findSafeTempDir() {
	var candidates []string

	err := processFilesystems(func(fstype, path string) error {
		if fstype == "tmpfs" &&
			syscall.Access(path, 7 /* write ok */) == nil {
			candidates = append(candidates, path)
		}

		return nil
	})

	if err == nil && len(candidates) == 0 {
		err = errors.New("no writable tmpfs directories found")
	}

	if err != nil {
		safeTempDirErr = errors.New("system: while checking filesystems: " + err.Error())
		return
	}

	suggested := os.TempDir()
	preferred := []string{suggested}
	var otherOptions []string
	if dir := os.Getenv("XDG_RUNTIME_DIR"); len(dir) > 0 {
		otherOptions = append(otherOptions, dir)
	}
	otherOptions = append(otherOptions, "/tmp", "/var/tmp")
	for _, d := range otherOptions {
		if suggested != d {
			preferred = append(preferred, d)
		}
	}

	for _, d := range preferred {
		for _, candidate := range candidates {
			if candidate == d {
				safeTempDir = candidate
				return
			}
		}
	}

	safeTempDir = candidates[0]
}

// SafeTempDir returns the path of a writable directory which is mounted with
// tmpfs. As long as the swap is encrypted, then it should be safe to write
// there.
func SafeTempDir() (string, error) {
	safeTempDirOnce.Do(findSafeTempDir)
	if safeTempDirErr != nil {
		return "", safeTempDirErr
	}
	return safeTempDir, nil
}
