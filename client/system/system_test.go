package system

import (
	"testing"
)

func TestSafe(t *testing.T) {
	if err := IsSafe(); err != nil {
		t.Errorf("IsSafe returned an error: %s", err)
	}
}

func TestSafeTempDir(t *testing.T) {
	_, err := SafeTempDir()
	if err != nil {
		t.Errorf("error while getting safe temp directory: %s", err)
	}
}
