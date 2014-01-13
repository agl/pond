package system

import (
	"bufio"
	"bytes"
	"errors"
	"os/exec"
	"strings"
)

func IsSafe() error {
	output, err := exec.Command("swapinfo").CombinedOutput()
	if err != nil {
		return errors.New("system: error when executing swapinfo: " + err.Error())
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Scan() // skip header line
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 1 {
			continue
		}
		device := fields[0]
		if strings.HasSuffix(device, ".bde") || strings.HasSuffix(device, ".eli") {
			continue
		}
		return errors.New("swapping is active on " + device + " which doesn't appear to be encrypted")
	}

	if err := scanner.Err(); err != nil {
		return errors.New("system: while parsing swapinfo output: " + err.Error())
	}
	return nil
}

func SafeTempDir() (string, error) {
	return "", errors.New("not implemented")
}
