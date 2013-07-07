package main

import (
	"fmt"
	"time"

	"github.com/agl/pond/client/disk"
	"github.com/agl/pond/client/tpm"
)

func (c *client) createErasureStorage(pw string, stateFile *disk.StateFile) error {
	var tpmInfo string
	present := tpm.Present()
	if present {
		tpmInfo = "Your computer appears to have a TPM chip. Click below to try and use it. You'll need tcsd (the TPM daemon) running."
	} else {
		tpmInfo = "Your computer does not appear to have a TPM chip. Without one, it's possible that someone in physical possession of your computer and passphrase could extract old messages that should have been deleted. Using a computer with a TPM is strongly preferable until alternatives can be implemented."
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
				text: "It's very difficult to erase information on modern computers so Pond tries to use the TPM chip if possible.\n\n" + tpmInfo,
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

	c.ui.Actions() <- SetBoxContents{name: "body", child: ui}
	c.ui.Actions() <- SetFocus{name: "tpm"}
	c.ui.Actions() <- UIState{uiStateErasureStorage}
	c.ui.Signal()

	var logText string

	tpm := disk.TPM{
		Log: func(format string, args ...interface{}) {
			c.log.Printf(format, args...)
			logText += fmt.Sprintf(format, args...) + "\n"
			c.ui.Actions() <- SetTextView{name: "log", text: logText}
			c.ui.Signal()
		},
		Rand: c.rand,
	}

NextEvent:
	for {
		event, ok := <-c.ui.Events()
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
				c.ui.Actions() <- SetTextView{name: "log", text: ""}
				c.ui.Signal()
				logText = ""
				time.Sleep(300 * time.Millisecond)
			}

			stateFile.Erasure = &tpm
			c.ui.Actions() <- Sensitive{name: "tpm", sensitive: false}
			c.ui.Actions() <- Sensitive{name: "continue", sensitive: false}
			c.ui.Signal()
			if err := stateFile.Create(pw); err != nil {
				tpm.Log("Setup failed with error: %s", err)
				tpm.Log("You can click the button to try again")
				c.ui.Actions() <- Sensitive{name: "tpm", sensitive: true}
				c.ui.Actions() <- Sensitive{name: "continue", sensitive: true}
				c.ui.Signal()
				continue NextEvent
			}
			return nil
		}
	}

	panic("unreachable")
}

