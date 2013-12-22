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

func (l *Log) clear() {
	l.Lock()
	defer l.Unlock()

	l.entries = nil
	l.epoch = 0
}
