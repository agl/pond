package system

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

func processMountOutput(f func(line string) error) error {
	contents, err := exec.Command("/sbin/mount").CombinedOutput()
	if err != nil {
		return err
	}

	file := bufio.NewReader(bytes.NewBuffer(contents))
	for {
		line, isPrefix, err := file.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if isPrefix {
			return errors.New("system: file contains a line that it too long to process")
		}
		if err = f(string(line)); err != nil {
			return err
		}
	}

	return nil
}

// IsSafe checks to see whether the current OS appears to be safe. Specifically
// it checks that any swap is encrypted.
func IsSafe() error {
	output, err := exec.Command("/sbin/sysctl", "vm.swapencrypt.enable").CombinedOutput()
	if err != nil {
		return errors.New("system: while checking sysctl output: " + err.Error())
	}
	if !strings.Contains(string(output), "vm.swapencrypt.enable=1") {
		return errors.New("system: vm.swapencrypt.enable is not set to 1.")
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

	err := processMountOutput(func(line string) error {
		fields := strings.Fields(line)
		if len(fields) < 1 {
			return nil
		}
		path := fields[2]
		filesystem := fields[4]
		if filesystem == "tmpfs" &&
			syscall.Access(path, 2 /* write ok */) == nil {
			candidates = append(candidates, path)
		}

		return nil
	})

	if err == nil && len(candidates) == 0 {
		err = errors.New("system: no writable tmpfs directories found")
	}

	if err != nil {
		safeTempDirErr = errors.New("system: while checking mount output: " + err.Error())
		return
	}

	suggested := os.TempDir()
	preferred := []string{suggested}
	var otherOptions []string
	otherOptions = append(otherOptions, "/tmp")
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
