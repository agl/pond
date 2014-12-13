// +build !nogui,!linux

// Any packages 

package main

import (
	"github.com/agl/pond/client/disk"
)

func (c *guiClient) createErasureStorage(pw string, stateFile *disk.StateFile) error {
	c.gui.Actions() <- UIState{uiStateErasureStorage}
	c.gui.Signal()

	return c.client.createErasureStorage(pw,stateFile)
}

