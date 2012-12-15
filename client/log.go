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
	updateChan chan bool
	toStderr   bool
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

func (l *Log) add(isError bool, format string, args ...interface{}) {
	l.Lock()
	defer l.Unlock()

	entry := logEntry{
		time.Now(),
		isError,
		fmt.Sprintf(format, args...),
	}
	l.entries = append(l.entries, entry)
	select {
	case l.updateChan <- true:
	default:
	}

	if l.toStderr {
		fmt.Fprintf(os.Stderr, "%s: %s\n", entry.Format(logTimeFormat), entry.s)
	}
}

func (c *client) logUI() interface{} {
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
			TextView{
				widgetBase: widgetBase{expand: true, fill: true, name: "log"},
				editable:   true,
			},
		},
	}

	log := ""
	lastProcessedIndex := -1
	for _, entry := range c.log.entries {
		log += fmt.Sprintf("%s: %s\n", entry.Format(logTimeFormat), entry.s)
		lastProcessedIndex++
	}

	c.ui.Actions() <- SetChild{name: "right", child: ui}
	c.ui.Actions() <- SetTextView{name: "log", text: log}
	c.ui.Actions() <- UIState{uiStateCompose}
	c.ui.Signal()

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
		for _, entry := range c.log.entries[lastProcessedIndex+1:] {
			log += fmt.Sprintf("%s: %s\n", entry.Format(logTimeFormat), entry.s)
			lastProcessedIndex++
		}
		c.log.Unlock()

		c.ui.Actions() <- SetTextView{name: "log", text: log}
		c.ui.Signal()
	}

	return nil
}
