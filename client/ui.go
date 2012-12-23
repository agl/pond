package main

const uiActionsQueueLen = 8

type UI interface {
	Actions() chan<- interface{}
	Events() <-chan interface{}
	Signal()
	Run()
}

type Widget interface {
	Name() string
	Padding() uint
	Expand() bool
	Fill() bool
	PackEnd() bool
	Foreground() uint32
	Background() uint32
	Focused() bool
}

type widgetBase struct {
	name                   string
	padding                uint
	expand, fill           bool
	packEnd                bool
	foreground, background uint32
	focused                bool
	insensitive            bool
	width, height          int
	font                   string
}

func (w widgetBase) Name() string {
	return w.name
}

func (w widgetBase) PackEnd() bool {
	return w.packEnd
}

func (w widgetBase) Padding() uint {
	return w.padding
}

func (w widgetBase) Expand() bool {
	return w.expand
}

func (w widgetBase) Fill() bool {
	return w.fill
}

func (w widgetBase) Foreground() uint32 {
	return w.foreground
}

func (w widgetBase) Background() uint32 {
	return w.background
}

func (w widgetBase) Focused() bool {
	return w.focused
}

type VBox struct {
	widgetBase
	homogeneous bool
	spacing     uint
	children    []Widget
}

type HBox struct {
	widgetBase
	homogeneous bool
	spacing     uint
	children    []Widget
}

type EventBox struct {
	widgetBase
	child Widget
}

type Label struct {
	widgetBase
	text           string
	size           int
	xAlign, yAlign float32
	wrap           int
	selectable     bool
}

type Entry struct {
	widgetBase
	text     string
	width    int
	password bool
}

type Button struct {
	widgetBase
	text  string
	image Indicator
}

type Spinner struct {
	widgetBase
}

type Paned struct {
	widgetBase
	left  Widget
	right Widget
}

type Scrolled struct {
	widgetBase
	child      Widget
	horizontal bool
	viewport   bool
}

type TextView struct {
	widgetBase
	editable       bool
	text           string
	wrap           bool
	updateOnChange bool
	spellCheck     bool
}

type Combo struct {
	widgetBase
	labels      []string
	preSelected string
}

type Image struct {
	widgetBase
	image          Indicator
	xAlign, yAlign float32
}

type Frame struct {
	widgetBase
	child Widget
}

type Progress struct {
	widgetBase
}

type Reset struct {
	root Widget
}

type Click struct {
	name      string
	entries   map[string]string
	textViews map[string]string
	combos    map[string]string
}

type Update struct {
	name string
	text string
}

type OpenResult struct {
	ok   bool
	path string
	arg  interface{}
}

type Append struct {
	name     string
	children []Widget
}

type AddToBox struct {
	box   string
	pos   int
	child Widget
}

type SetChild struct {
	name  string
	child Widget
}

type SetBoxContents struct {
	name  string
	child Widget
}

type Sensitive struct {
	name      string
	sensitive bool
}

type SetBackground struct {
	name  string
	color uint32
}

type StartSpinner struct {
	name string
}

type StopSpinner struct {
	name string
}

type SetText struct {
	name string
	text string
}

type SetEntry struct {
	name string
	text string
}

type SetTextView struct {
	name string
	text string
}

type SetImage struct {
	name  string
	image Indicator
}

type SetFocus struct {
	name string
}

type Destroy struct {
	name string
}

type FileOpen struct {
	save  bool
	title string
	arg   interface{}
}

type SetForeground struct {
	name       string
	foreground uint32
}

type SetProgress struct {
	name     string
	fraction float64
}

type UIState struct {
	stateID int
}

type UIError struct {
	err error
}
