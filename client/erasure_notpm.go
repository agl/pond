// +build notpm

package main

import (
	"github.com/agl/pond/client/disk"
)

func (c *client) createErasureStorage(pw string, stateFile *disk.StateFile) error {
	return stateFile.Create(pw)
}

func (c *client) hasErasure() bool {
	return false
}
