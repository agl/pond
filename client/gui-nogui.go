// +build nogui

package main

import "io"

const haveGUI = false

type noGUIClient struct {
	client
	dev bool
}

type GUI int

func (GUI) Run() {
}

func NewGTKUI() GUI {
	return 0
}

func (*noGUIClient) Start() {
}

func NewGUIClient(stateFilename string, gui GUI, rand io.Reader, testing, autoFetch bool) *noGUIClient {
	panic("no GUI built")
}
