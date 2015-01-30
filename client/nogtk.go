// +build nogtk

package main

type GTKUI struct{}

func NewGTKUI() *GTKUI { return &GTKUI{} }

func (ui *GTKUI) Run() {
	panic("not implemented")
}

func (ui *GTKUI) Actions() chan<- interface{} {
	panic("not implemented")
}

func (ui *GTKUI) Events() <-chan interface{} {
	panic("not implemented")
}

func (ui *GTKUI) Signal() {
	panic("not implemented")
}
