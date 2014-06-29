package main

import (
	"github.com/agl/pond/client/disk"
)

func (c *client) createErasureStorage(pw string, stateFile *disk.StateFile) error {
	// No NVRAM support on FreeBSD yet.
	return stateFile.Create(pw)
}
