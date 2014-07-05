// +build !nogui,linux,!notpm

package main

import (
	"fmt"
	"time"

	"github.com/agl/pond/client/disk"
	"github.com/agl/pond/client/tpm"
)

func (c *guiClient) createErasureStorage(pw string, stateFile *disk.StateFile) error {
	var tpmInfo string
	present := tpm.Present()
	if present {
		tpmInfo = tpmPresentMsg
	} else {
		tpmInfo = tpmNotPresentMsg
	}

	ui := VBox{
		widgetBase: widgetBase{padding: 40, expand: true, fill: true, name: "vbox"},
		children: []Widget{
			Label{
				widgetBase: widgetBase{font: "DejaVu Sans 30"},
				text:       "Configure TPM",
			},
			Label{
				widgetBase: widgetBase{
					padding: 20,
					font:    "DejaVu Sans 14",
				},
				text: tpmIntroMsg + "\n\n" + tpmInfo,
				wrap: 600,
			},
			HBox{
				children: []Widget{
					Button{
						widgetBase: widgetBase{
							name:        "tpm",
							insensitive: !present,
						},
						text: "Try to configure TPM",
					},
				},
			},
			TextView{
				widgetBase: widgetBase{name: "log", expand: true, fill: true},
				editable:   false,
			},
			Button{
				widgetBase: widgetBase{name: "continue"},
				text:       "Continue without TPM",
			},
		},
	}

	c.gui.Actions() <- SetBoxContents{name: "body", child: ui}
	c.gui.Actions() <- SetFocus{name: "tpm"}
	c.gui.Actions() <- UIState{uiStateErasureStorage}
	c.gui.Signal()

	var logText string

	tpm := disk.TPM{
		Log: func(format string, args ...interface{}) {
			c.log.Printf(format, args...)
			logText += fmt.Sprintf(format, args...) + "\n"
			c.gui.Actions() <- SetTextView{name: "log", text: logText}
			c.gui.Signal()
		},
		Rand: c.rand,
	}

NextEvent:
	for {
		event, ok := <-c.gui.Events()
		if !ok {
			c.ShutdownAndSuspend()
		}

		click, ok := event.(Click)
		if !ok {
			continue
		}

		switch click.name {
		case "continue":
			stateFile.Erasure = nil
			return stateFile.Create(pw)
		case "tpm":
			if len(logText) > 0 {
				c.gui.Actions() <- SetTextView{name: "log", text: ""}
				c.gui.Signal()
				logText = ""
				time.Sleep(300 * time.Millisecond)
			}

			stateFile.Erasure = &tpm
			c.gui.Actions() <- Sensitive{name: "tpm", sensitive: false}
			c.gui.Actions() <- Sensitive{name: "continue", sensitive: false}
			c.gui.Signal()
			if err := stateFile.Create(pw); err != nil {
				tpm.Log("Setup failed with error: %s", err)
				tpm.Log("You can click the button to try again")
				c.gui.Actions() <- Sensitive{name: "tpm", sensitive: true}
				c.gui.Actions() <- Sensitive{name: "continue", sensitive: true}
				c.gui.Signal()
				continue NextEvent
			}
			return nil
		}
	}

	panic("unreachable")
}
