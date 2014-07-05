// +build !notpm

package main

import (
	"fmt"

	"github.com/agl/pond/client/disk"
	"github.com/agl/pond/client/tpm"
)

func (c *cliClient) createErasureStorage(pw string, stateFile *disk.StateFile) error {
	c.Printf("%s %s\n", termInfoPrefix, tpmIntroMsg)

	present := tpm.Present()
	if !present {
		c.Printf("%s %s\n", termErrPrefix, tpmNotPresentMsg)
	} else {
		c.Printf("%s %s\n", termInfoPrefix, tpmPresentMsg)
	}

ConfigureLoop:
	for present {
		c.term.SetPrompt("Try to configure TPM (y/n)> ")

	PromptLoop:
		for {
			line, err := c.term.ReadLine()
			if err != nil {
				return err
			}
			switch line {
			case "y", "yes", "Yes":
				break PromptLoop
			case "n", "no", "No":
				break ConfigureLoop
			}
		}

		tpm := disk.TPM{
			Log: func(format string, args ...interface{}) {
				msg := fmt.Sprintf(format, args...)
				c.Printf("%s\n", terminalEscape(msg, false))
			},
			Rand: c.rand,
		}

		stateFile.Erasure = &tpm
		if err := stateFile.Create(pw); err != nil {
			c.Printf("%s Setup failed with error: %s\n", termErrPrefix, terminalEscape(err.Error(), false))
		} else {
			c.Printf("%s TPM in use for this statefile\n", termInfoPrefix)
			return nil
		}
	}

	c.Printf("%s TPM will not be used for this statefile\n", termErrPrefix)
	stateFile.Erasure = nil
	return stateFile.Create(pw)
}
