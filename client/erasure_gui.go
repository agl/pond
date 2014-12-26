// +build !nogui,!linux

// Any build options that posses their own createErasureStorage should be excluded above.

package main

import (
	"github.com/agl/pond/client/disk"
)

func (c *guiClient) createErasureStorage(pw string, stateFile *disk.StateFile) error {
	c.gui.Actions() <- UIState{uiStateErasureStorage}
	c.gui.Signal()

	return c.client.createErasureStorage(pw,stateFile)
}

