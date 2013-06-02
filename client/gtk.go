package main

import (
	"fmt"
	"strconv"
	"syscall"

	"github.com/agl/go-gtk/gdk"
	"github.com/agl/go-gtk/glib"
	"github.com/agl/go-gtk/gtk"
	"github.com/agl/go-gtk/gtkspell"
)

type GTKUI struct {
	window    *gtk.GtkWindow
	actions   chan interface{}
	events    chan interface{}
	pipe      [2]int
	topWidget gtk.WidgetLike
	widgets   map[string]gtk.WidgetLike
	entries   map[string]*gtk.GtkEntry
	textViews map[string]*gtk.GtkTextView
	combos    map[string]*gtk.GtkComboBoxText
}

func NewGTKUI() *GTKUI {
	gtk.Init(nil)
	window := gtk.Window(gtk.GTK_WINDOW_TOPLEVEL)
	window.SetPosition(gtk.GTK_WIN_POS_CENTER)
	window.SetTitle("Pond")
	window.SetDefaultSize(640, 480)

	ui := &GTKUI{
		window:  window,
		actions: make(chan interface{}, uiActionsQueueLen),
		events:  make(chan interface{}, 8),
	}
	window.Connect("destroy", func(ctx *glib.CallbackContext) {
		close(ui.events)
		for {
			if _, ok := <-ui.actions; !ok {
				break
			}
		}
		gtk.MainQuit()
	})
	if err := syscall.Pipe(ui.pipe[:]); err != nil {
		panic(err)
	}
	syscall.SetNonblock(ui.pipe[0], true)

	glib.FdWatchAdd(ui.pipe[0], glib.IOIn, func(conditions int) bool {
		ui.onAction()
		return true
	})

	return ui
}

func (ui *GTKUI) Actions() chan<- interface{} {
	return ui.actions
}

func (ui *GTKUI) Events() <-chan interface{} {
	return ui.events
}

func (ui *GTKUI) Signal() {
	syscall.Write(ui.pipe[1], []byte{0})
}

func (ui *GTKUI) Run() {
	gtk.Main()
}

func (ui *GTKUI) onAction() {
	buf := make([]byte, 8)
	for {
		n, _ := syscall.Read(ui.pipe[0], buf)
		if n < 1 {
			break
		}
	}

	for {
		select {
		case v, ok := <-ui.actions:
			if !ok {
				gtk.MainQuit()
				return
			}
			ui.handle(v)
		default:
			return
		}
	}
}

func (ui *GTKUI) updated(name string) {
	buf := ui.textViews[name].GetBuffer()
	var start, end gtk.GtkTextIter
	buf.GetStartIter(&start)
	buf.GetEndIter(&end)
	contents := buf.GetText(&start, &end, false)
	ui.events <- Update{name, contents}
}

func (ui *GTKUI) clicked(name string) {
	entries := make(map[string]string)
	textViews := make(map[string]string)
	combos := make(map[string]string)

	for ename, entry := range ui.entries {
		entries[ename] = entry.GetText()
	}
	for tvname, tv := range ui.textViews {
		buf := tv.GetBuffer()
		var start, end gtk.GtkTextIter
		buf.GetStartIter(&start)
		buf.GetEndIter(&end)
		textViews[tvname] = buf.GetText(&start, &end, false)
	}
	for comboName, combo := range ui.combos {
		combos[comboName] = combo.GetActiveText()
	}

	ui.events <- Click{name, entries, textViews, combos}
}

func (ui *GTKUI) newWidget(v Widget) gtk.WidgetLike {
	widget := ui.createWidget(v)
	if name := v.Name(); len(name) > 0 {
		ui.widgets[name] = widget
	}
	return widget
}

func alignToGTK(align int) gtk.GtkAlign {
	switch align {
	case AlignStart:
		return gtk.GTK_ALIGN_START
	case AlignEnd:
		return gtk.GTK_ALIGN_END
	case AlignFill:
		return gtk.GTK_ALIGN_FILL
	case AlignCenter:
		return gtk.GTK_ALIGN_CENTER
	}

	panic("bad alignment value")
}

func configureWidget(w *gtk.GtkWidget, b widgetBase) {
	width := -1
	if b.width != 0 {
		width = b.width
	}

	height := -1
	if b.height != 0 {
		height = b.height
	}

	if width != -1 || height != -1 {
		w.SetSizeRequest(width, height)
	}

	w.SetSensitive(!b.insensitive)

	if color := b.Foreground(); color != 0 {
		w.ModifyFG(gtk.GTK_STATE_NORMAL, toColor(color))
	}
	if color := b.Background(); color != 0 {
		w.ModifyBG(gtk.GTK_STATE_NORMAL, toColor(color))
	}
	if len(b.font) != 0 {
		w.ModifyFontEasy(b.font)
	}
	if b.hExpand {
		w.SetHExpand(true)
	}
	if b.vExpand {
		w.SetVExpand(true)
	}
	if b.margin > 0 {
		w.SetMargin(b.margin)
	}
	if b.marginTop > 0 {
		w.SetMarginTop(b.marginTop)
	}
	if b.marginBottom > 0 {
		w.SetMarginBottom(b.marginBottom)
	}
	if b.marginLeft > 0 {
		w.SetMarginLeft(b.marginLeft)
	}
	if b.vAlign != AlignNone {
		w.SetVAlign(alignToGTK(b.vAlign))
	}
	if b.hAlign != AlignNone {
		w.SetHAlign(alignToGTK(b.hAlign))
	}
}

func (ui *GTKUI) createWidget(v interface{}) gtk.WidgetLike {
	switch v := v.(type) {
	case VBox:
		vbox := gtk.Box(gtk.GTK_ORIENTATION_VERTICAL, v.spacing)
		for _, child := range v.children {
			widget := ui.newWidget(child)
			if child.PackEnd() {
				vbox.PackEnd(widget, child.Expand(), child.Fill(), child.Padding())
			} else {
				vbox.PackStart(widget, child.Expand(), child.Fill(), child.Padding())
			}
		}
		return vbox
	case HBox:
		hbox := gtk.Box(gtk.GTK_ORIENTATION_HORIZONTAL, v.spacing)
		for _, child := range v.children {
			widget := ui.newWidget(child)
			hbox.PackStart(widget, child.Expand(), child.Fill(), child.Padding())
		}
		return hbox
	case EventBox:
		box := gtk.EventBox()
		if v.child != nil {
			widget := ui.newWidget(v.child)
			box.Add(widget)
		}
		configureWidget(&box.GtkWidget, v.widgetBase)
		if len(v.name) > 0 {
			box.Connect("button-press-event", func(e interface{}) {
				ui.clicked(v.name)
			})
		}
		return box
	case Label:
		label := gtk.Label(v.text)
		label.SetAlignment(v.xAlign, v.yAlign)
		configureWidget(&label.GtkWidget, v.widgetBase)
		if v.wrap != 0 {
			label.SetSizeRequest(v.wrap, -1)
			label.SetLineWrap(true)
		}
		label.SetSelectable(v.selectable)
		return label
	case Entry:
		entry := gtk.Entry()
		entry.SetText(v.text)
		if v.width > 0 {
			entry.SetWidthChars(v.width)
		}
		if name := v.name; len(name) > 0 {
			ui.entries[name] = entry
			entry.Connect("destroy", func() {
				delete(ui.entries, name)
			})
			entry.Connect("activate", func() {
				ui.clicked(v.name)
			})
		}
		if v.password {
			entry.SetVisibility(false)
		}
		configureWidget(&entry.GtkWidget, v.widgetBase)
		return entry
	case Button:
		var button *gtk.GtkButton
		if len(v.text) > 0 {
			button = gtk.ButtonWithLabel(v.text)
		} else {
			button = gtk.Button()
		}
		if v.image != indicatorNone {
			image := gtk.ImageFromPixbuf(v.image.Image())
			button.Add(image)
		}
		button.Clicked(func() {
			ui.clicked(v.name)
		})
		configureWidget(&button.GtkWidget, v.widgetBase)
		return button
	case Spinner:
		spinner := gtk.Spinner()
		spinner.Start()
		return spinner
	case Paned:
		paned := gtk.Paned(gtk.GTK_ORIENTATION_HORIZONTAL)
		left := ui.newWidget(v.left)
		right := ui.newWidget(v.right)
		paned.Add1(left)
		paned.Add2(right)
		return paned
	case Scrolled:
		scrolled := gtk.ScrolledWindow(nil, nil)
		horizonalPolicy := gtk.GtkPolicyType(gtk.GTK_POLICY_NEVER)
		if v.horizontal {
			horizonalPolicy = gtk.GTK_POLICY_AUTOMATIC
		}
		scrolled.SetPolicy(horizonalPolicy, gtk.GTK_POLICY_AUTOMATIC)
		child := ui.newWidget(v.child)
		if v.viewport {
			scrolled.AddWithViewPort(child)
		} else {
			scrolled.Add(child)
		}
		return scrolled
	case TextView:
		view := gtk.TextView()
		view.SetBorderWidth(1)
		view.SetEditable(v.editable)
		if len(v.text) > 0 {
			buffer := gtk.TextBuffer(gtk.TextTagTable())
			buffer.SetText(v.text)
			view.SetBuffer(buffer)
		}
		if v.wrap {
			view.SetWrapMode(gtk.GTK_WRAP_WORD_CHAR)
		}
		if v.updateOnChange && len(v.name) > 0 {
			view.GetBuffer().Connect("changed", func() {
				ui.updated(v.name)
			})
		}
		if v.spellCheck {
			if _, err := gtkspell.New(view, ""); err != nil {
				panic(err)
			}
		}
		if name := v.name; len(name) > 0 {
			ui.textViews[name] = view
			view.Connect("destroy", func() {
				delete(ui.textViews, name)
			})
		}
		configureWidget(&view.GtkWidget, v.widgetBase)
		return view
	case Combo:
		combo := gtk.ComboBoxText()
		selectedIndex := -1
		for i, l := range v.labels {
			combo.AppendText(l)
			if len(v.preSelected) > 0 && l == v.preSelected {
				selectedIndex = i
			}
		}
		if selectedIndex >= 0 {
			combo.SetActive(selectedIndex)
		}
		if name := v.name; len(name) > 0 {
			ui.combos[name] = combo
			combo.Connect("destroy", func() {
				delete(ui.combos, name)
			})
			combo.Connect("changed", func() {
				ui.clicked(v.name)
			})
		}
		configureWidget(&combo.GtkWidget, v.widgetBase)
		return combo
	case Image:
		image := gtk.ImageFromPixbuf(v.image.Image())
		image.SetAlignment(v.xAlign, v.yAlign)
		configureWidget(&image.GtkWidget, v.widgetBase)
		return image
	case Frame:
		frame := gtk.Frame("")
		configureWidget(&frame.GtkWidget, v.widgetBase)
		if v.child != nil {
			widget := ui.newWidget(v.child)
			frame.Add(widget)
		}
		return frame
	case Progress:
		pro := gtk.ProgressBar()
		configureWidget(&pro.GtkWidget, v.widgetBase)
		return pro
	case Grid:
		grid := gtk.Grid()
		configureWidget(&grid.GtkWidget, v.widgetBase)
		for y, row := range v.rows {
			x := 0
			for _, elem := range row {
				if elem.widget != nil {
					grid.Attach(ui.newWidget(elem.widget), x, y, elem.width, elem.height)
				}
				x += elem.width
			}
		}
		if v.rowSpacing > 0 {
			grid.SetRowSpacing(v.rowSpacing)
		}
		if v.colSpacing > 0 {
			grid.SetColSpacing(v.colSpacing)
		}
		return grid
	default:
		panic("unknown widget: " + fmt.Sprintf("%#v", v))
	}

	panic("forgot to return")
}

func (ui *GTKUI) getWidget(name string) gtk.WidgetLike {
	widget, ok := ui.widgets[name]
	if !ok {
		panic("no such widget: " + name)
	}
	return widget
}

func (ui *GTKUI) handle(action interface{}) {
	switch action := action.(type) {
	case Reset:
		ui.widgets = make(map[string]gtk.WidgetLike)
		ui.entries = make(map[string]*gtk.GtkEntry)
		ui.textViews = make(map[string]*gtk.GtkTextView)
		ui.combos = make(map[string]*gtk.GtkComboBoxText)
		if ui.topWidget != nil {
			ui.window.Remove(ui.topWidget)
			ui.topWidget = nil
		}
		ui.topWidget = ui.newWidget(action.root)
		ui.window.Add(ui.topWidget)
		ui.window.ShowAll()
	case Append:
		box := ui.getWidget(action.name).(gtk.BoxLike)
		for _, child := range action.children {
			widget := ui.newWidget(child)
			box.PackStart(widget, child.Expand(), child.Fill(), child.Padding())
		}
		ui.window.ShowAll()
	case AddToBox:
		box := ui.getWidget(action.box).(gtk.BoxLike)
		widget := ui.newWidget(action.child)
		box.PackStart(widget, action.child.Expand(), action.child.Fill(), action.child.Padding())
		box.ReorderChild(widget, action.pos)
		ui.window.ShowAll()
	case SetChild:
		bin := gtk.GtkBin{gtk.GtkContainer{gtk.GtkWidget{ui.getWidget(action.name).ToNative()}}}
		for _, child := range bin.GetChildren() {
			child.Destroy()
		}
		bin.Add(ui.newWidget(action.child))
		ui.window.ShowAll()
	case SetBoxContents:
		box := gtk.GtkBox{gtk.GtkContainer{gtk.GtkWidget{ui.getWidget(action.name).ToNative()}}}
		for _, child := range box.GetChildren() {
			child.Destroy()
		}
		child := action.child
		widget := ui.newWidget(child)
		box.PackStart(widget, child.Expand(), child.Fill(), child.Padding())
		ui.window.ShowAll()
	case SetBackground:
		widget := gtk.GtkWidget{ui.getWidget(action.name).ToNative()}
		widget.ModifyBG(gtk.GTK_STATE_NORMAL, toColor(action.color))
	case Sensitive:
		widget := gtk.GtkWidget{ui.getWidget(action.name).ToNative()}
		widget.SetSensitive(action.sensitive)
	case StartSpinner:
		widget := gtk.GtkSpinner{gtk.GtkWidget{ui.getWidget(action.name).ToNative()}}
		widget.Start()
	case StopSpinner:
		widget := gtk.GtkSpinner{gtk.GtkWidget{ui.getWidget(action.name).ToNative()}}
		widget.Stop()
	case SetText:
		widget := gtk.GtkLabel{gtk.GtkWidget{ui.getWidget(action.name).ToNative()}}
		widget.SetText(action.text)
	case SetEntry:
		widget := ui.getWidget(action.name).(gtk.TextInputLike)
		widget.SetText(action.text)
	case SetTextView:
		widget := gtk.GtkTextView{gtk.GtkContainer{gtk.GtkWidget{ui.getWidget(action.name).ToNative()}}}
		buffer := gtk.TextBuffer(gtk.TextTagTable())
		buffer.SetText(action.text)
		widget.SetBuffer(buffer)
	case SetImage:
		widget := gtk.GtkImage{gtk.GtkWidget{ui.getWidget(action.name).ToNative()}}
		widget.SetFromPixbuf(action.image.Image())
	case SetFocus:
		widget := gtk.GtkWidget{ui.getWidget(action.name).ToNative()}
		widget.GrabFocus()
	case Destroy:
		widget := gtk.GtkWidget{ui.getWidget(action.name).ToNative()}
		widget.Destroy()
		delete(ui.widgets, action.name)
	case FileOpen:
		fileAction := gtk.GTK_FILE_CHOOSER_ACTION_OPEN
		but := gtk.GTK_STOCK_OPEN
		if action.save {
			fileAction = gtk.GTK_FILE_CHOOSER_ACTION_SAVE
			but = gtk.GTK_STOCK_SAVE
		}
		dialog := gtk.FileChooserDialog(action.title, ui.window, fileAction, gtk.GTK_STOCK_CANCEL, int(gtk.GTK_RESPONSE_CANCEL), but, int(gtk.GTK_RESPONSE_ACCEPT))
		switch gtk.GtkResponseType(dialog.Run()) {
		case gtk.GTK_RESPONSE_ACCEPT:
			ui.events <- OpenResult{
				ok:   true,
				path: dialog.GetFilename(),
				arg:  action.arg,
			}
		default:
			ui.events <- OpenResult{arg: action.arg}
		}
		dialog.Destroy()
	case SetForeground:
		widget := gtk.GtkWidget{ui.getWidget(action.name).ToNative()}
		widget.ModifyFG(gtk.GTK_STATE_NORMAL, toColor(action.foreground))
	case SetProgress:
		widget := gtk.GtkProgressBar{gtk.GtkWidget{ui.getWidget(action.name).ToNative()}}
		widget.SetFraction(action.fraction)
		widget.SetText(action.s)
	case SetTitle:
		ui.window.SetTitle(action.title)
	case InsertRow:
		grid := gtk.GtkGrid{gtk.GtkContainer{gtk.GtkWidget{ui.getWidget(action.name).ToNative()}}}
		x := 0
		for _, elem := range action.row {
			if elem.widget != nil {
				grid.Attach(ui.newWidget(elem.widget), x, action.pos, elem.width, elem.height)
			}
			x += elem.width
		}
		ui.window.ShowAll()

	case UIError:
	case UIState:
		// for testing.
	default:
		panic("unknown action")
	}
}

func toColor(color uint32) *gdk.GdkColor {
	return gdk.Color("#" + strconv.FormatUint(uint64(color), 16))
}
