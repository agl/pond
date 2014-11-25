// +build !nogui

package main

const uiActionsQueueLen = 256

// GUI contains an abstraction layer that models GTK pretty closely.  This is
// used to allow the GUI to run in a separate goroutine and also to allow
// unittesting.
type GUI interface {
	// Actions returns a channel to which GUI actions can be written for
	// execution by the GUI.
	Actions() chan<- interface{}
	// Events returns a channel from which events from the GUI can be read.
	Events() <-chan interface{}
	// Signal causes the GUI to process pending actions that have been
	// written to the channel returned by Actions(). The GUI may process
	// actions at any time but calling Signal ensures that all actions
	// currently pending will be executed. Signal does not wait for
	// pending actions to complete.
	Signal()
	// Run() starts the GUI's main loop and never returns.
	Run()
}

const (
	AlignNone = iota
	AlignStart
	AlignEnd
	AlignFill
	AlignCenter
)

// Widgets
//
// Widget structures mirror the similar widgets in GTK+ and their members
// mirror GTK+ properties. The GTK+ documentation is the best source of
// information.

// Widget is the base type of all widgets. It's sole implementation should be
// widgetBase, which should itself be embedded in all structs that represent
// widgets.
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
	// name contains a freeform identifier for a widget. The name should be
	// unique across all widgets that are currently live.
	name                   string
	padding                uint
	expand, fill           bool
	packEnd                bool
	foreground, background uint32
	focused                bool
	insensitive            bool
	width, height          int
	font                   string
	hExpand, vExpand       bool
	margin                 int
	marginTop              int
	marginBottom           int
	marginLeft             int
	vAlign, hAlign         int
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
	spacing  uint
	children []Widget
}

type HBox struct {
	widgetBase
	spacing  uint
	children []Widget
}

type EventBox struct {
	widgetBase
	child Widget
}

type Label struct {
	widgetBase
	text           string
	markup         string
	size           int
	xAlign, yAlign float32
	wrap           int
	selectable     bool
}

type Entry struct {
	widgetBase
	text           string
	width          int
	password       bool
	updateOnChange bool
}

type Button struct {
	widgetBase
	text   string
	markup string
	image  Indicator
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

type Grid struct {
	widgetBase
	rows           [][]GridE
	rowSpacing     int
	colSpacing     int
	rowHomogeneous bool
	colHomogeneous bool
}

type GridE struct {
	width  int
	height int
	widget Widget
}

type RadioGroup struct {
	widgetBase
	labels []string
}

type Calendar struct {
	widgetBase
}

type SpinButton struct {
	widgetBase
	min, max, step float64
}

type CheckButton struct {
	widgetBase
	checked bool
	text    string
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

// Actions
//
// These structures can be sent on the channel returned by Actions() in order
// to perform GUI actions.

// InsertRow adds an extra row to a Grid.
type InsertRow struct {
	name string
	pos  int
	row  []GridE
}

// GridSet sets the element at the given position in the grid.
type GridSet struct {
	name     string
	col, row int
	widget   Widget
}

// Reset replaces the top-level widget with root.
type Reset struct {
	root Widget
}

// Append adds widgets to a named, container widget.
type Append struct {
	name     string
	children []Widget
}

// AddToBox adds a child widget at a specific location in a box widget.
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

type SetChecked struct {
	name    string
	checked bool
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

type SetButtonText struct {
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

type ScrollTextViewToEnd struct {
	name string
}

type Destroy struct {
	name string
}

// FileOpen starts a file dialog.
type FileOpen struct {
	save  bool
	title string
	// filename contains the suggested filename in the case that save is
	// true.
	filename string
	// arg is an arbitary value that is passed in the corresponding
	// OpenResult event.
	arg interface{}
}

type SetForeground struct {
	name       string
	foreground uint32
}

type SetProgress struct {
	name     string
	fraction float64
	s        string
}

type SetTitle struct {
	title string
}

// UIState is a message that is ignored by a real GUI, but is used for
// synchronisation with unittests.
type UIState struct {
	stateID int
}

// UIError is a message that is ignored by a real GUI, but is used for
// communication with unittests.
type UIError struct {
	err error
}

// UIInfo is used for passing information to the unittests.
type UIInfo struct {
	info string
}

// Events
//
// Events are received on the channel returned by Events().

// Click is a very generic event that can be triggered by any sort of
// activation - not just mouse clicks. Because the GUI abstraction is
// asynchronous, the Click message contains the state of the GUI at the time of
// the click. Otherwise, further messages to obtain the state of other widgets
// at the time of the event would return the current values, as opposed to the
// values at the event time.
type Click struct {
	name        string
	entries     map[string]string
	textViews   map[string]string
	combos      map[string]string
	checks      map[string]bool
	radios      map[string]int
	calendars   map[string]CalendarDate
	spinButtons map[string]int
}

type CalendarDate struct {
	year, month, day int
}

// Update can result when the contents of a text entry are changed.
type Update struct {
	name string
	text string
}

// OpenResult results from the completion of a file dialog.
type OpenResult struct {
	ok   bool
	path string
	arg  interface{}
}
