package system

import (
	"errors"
)

func IsSafe() error {
	return errors.New("not implemented")
}

func SafeTempDir() (string, error) {
	return "", errors.New("not implemented")
}
