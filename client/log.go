package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

type logEntry struct {
	time.Time
	isError bool
	s       string
}

type Log struct {
	sync.Mutex
	entries    []logEntry
	epoch      uint64
	updateChan chan bool
	toStderr   bool
	// name is set in tests to an opaque identifer for this client. It's
	// prepended to log messages in order to aid debugging.
	name string
}

func NewLog() *Log {
	return &Log{
		updateChan: make(chan bool, 1),
	}
}

func (l *Log) Printf(format string, args ...interface{}) {
	l.add(false, format, args...)
}

func (l *Log) Errorf(format string, args ...interface{}) {
	l.add(true, format, args...)
}

const (
	// logLimit is the maximum number of entries in the log.
	logLimit = 500
	// logSlack is the number of entries past the maximum that we'll allow
	// before the log is recompacted down to logLimit enties.
	logSlack = 250
)

func (l *Log) add(isError bool, format string, args ...interface{}) {
	l.Lock()
	defer l.Unlock()

	entry := logEntry{
		time.Now(),
		isError,
		fmt.Sprintf(format, args...),
	}
	if len(l.entries) > logLimit+logSlack {
		newEntries := make([]logEntry, logLimit)
		copy(newEntries, l.entries[logSlack:])
		l.entries = newEntries
		l.epoch++
	}
	l.entries = append(l.entries, entry)
	select {
	case l.updateChan <- true:
	default:
	}

	if l.toStderr {
		var name string
		if len(l.name) != 0 {
			name = fmt.Sprintf("(%s) ", l.name)
		}
		fmt.Fprintf(os.Stderr, "%s%s: %s\n", name, entry.Format(logTimeFormat), entry.s)
	}
}

func (c *guiClient) logUI() interface{} {
	ui := VBox{
		children: []Widget{
			EventBox{
				widgetBase: widgetBase{background: colorHeaderBackground},
				child: VBox{
					children: []Widget{
						HBox{
							widgetBase: widgetBase{padding: 10},
							children: []Widget{
								Label{
									widgetBase: widgetBase{font: "Arial 16", padding: 10, foreground: colorHeaderForeground},
									text:       "ACTIVITY LOG",
								},
							},
						},
					},
				},
			},
			EventBox{widgetBase: widgetBase{height: 1, background: colorSep}},
			HBox{
				children: []Widget{
					VBox{
						widgetBase: widgetBase{
							expand: true,
							fill:   true,
						},
					},
					VBox{
						widgetBase: widgetBase{
							padding: 10,
						},
						children: []Widget{
							Button{
								widgetBase: widgetBase{
									name:    "transact",
									padding: 2,
								},
								text: "Transact Now",
							},
						},
					},
				},
			},
			Scrolled{
				horizontal: true,
				widgetBase: widgetBase{expand: true, fill: true},
				child: TextView{
					widgetBase: widgetBase{expand: true, fill: true, name: "log"},
					editable:   true,
				},
			},
		},
	}

	log := ""
	lastProcessedIndex := -1

	c.log.Lock()
	logEpoch := c.log.epoch
	for _, entry := range c.log.entries {
		log += fmt.Sprintf("%s: %s\n", entry.Format(logTimeFormat), entry.s)
		lastProcessedIndex++
	}
	c.log.Unlock()

	c.gui.Actions() <- SetChild{name: "right", child: ui}
	c.gui.Actions() <- SetTextView{name: "log", text: log}
	c.gui.Actions() <- UIState{uiStateLog}
	c.gui.Signal()

	for {
		event, wanted := c.nextEvent()
		if wanted {
			return event
		}

		if click, ok := event.(Click); ok && click.name == "transact" {
			select {
			case c.fetchNowChan <- nil:
			default:
			}
			continue
		}

		c.log.Lock()
		if logEpoch != c.log.epoch {
			logEpoch = c.log.epoch
			lastProcessedIndex = -1
			log = ""
		}
		for _, entry := range c.log.entries[lastProcessedIndex+1:] {
			log += fmt.Sprintf("%s: %s\n", entry.Format(logTimeFormat), entry.s)
			lastProcessedIndex++
		}
		c.log.Unlock()

		c.gui.Actions() <- SetTextView{name: "log", text: log}
		c.gui.Signal()
	}

	return nil
}
