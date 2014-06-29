// +build !nogui

package main

import (
	"strconv"
)

// listUI manages the sections in the left-hand side list. It contains a number
// of items, which may have subheadlines and indicators (coloured dots).
type listUI struct {
	gui        GUI
	vboxName   string
	entries    []listItem
	selected   uint64
	nextId     int
	hasSubline bool
}

type listItem struct {
	id                                                                           uint64
	name, sepName, boxName, imageName, lineName, sublineTextName, sublineBoxName string
	insensitive                                                                  bool
	hasSubline                                                                   bool
	background                                                                   uint32
}

func (cs *listUI) Event(event interface{}) (uint64, bool) {
	if click, ok := event.(Click); ok {
		for _, entry := range cs.entries {
			if click.name == entry.boxName {
				if entry.insensitive {
					return 0, false
				}
				return entry.id, true
			}
		}
	}

	return 0, false
}

func sublineLabel(name, text string) Label {
	return Label{
		widgetBase: widgetBase{
			padding:    5,
			foreground: colorSubline,
			font:       fontListSubline,
			name:       name,
		},
		text: text,
	}
}

func (cs *listUI) Add(id uint64, name, subline string, indicator Indicator) {
	c := listItem{
		id:              id,
		name:            name,
		sepName:         cs.newIdent(),
		boxName:         cs.newIdent(),
		imageName:       cs.newIdent(),
		lineName:        cs.newIdent(),
		sublineTextName: cs.newIdent(),
		sublineBoxName:  cs.newIdent(),
		background:      colorGray,
		hasSubline:      len(subline) > 0,
	}
	cs.entries = append(cs.entries, c)
	index := len(cs.entries) - 1

	if index > 0 {
		// Add the separator bar.
		cs.gui.Actions() <- AddToBox{
			box:   cs.vboxName,
			pos:   index*2 - 1,
			child: EventBox{widgetBase: widgetBase{height: 1, background: 0xe5e6e6, name: c.sepName}},
		}
	}

	children := []Widget{
		HBox{
			widgetBase: widgetBase{padding: 1},
			children: []Widget{
				Label{
					widgetBase: widgetBase{
						name:    c.lineName,
						padding: 5,
						font:    fontListEntry,
					},
					text: name,
				},
			},
		},
	}

	var sublineChildren []Widget

	if len(subline) > 0 {
		sublineChildren = append(sublineChildren, sublineLabel(c.sublineTextName, subline))
	}

	sublineChildren = append(sublineChildren, Image{
		widgetBase: widgetBase{
			padding: 4,
			expand:  true,
			fill:    true,
			name:    c.imageName,
		},
		image:  indicator,
		xAlign: 1,
		yAlign: 0.5,
	})

	children = append(children, HBox{
		widgetBase: widgetBase{padding: 1, name: c.sublineBoxName},
		children:   sublineChildren,
	})

	cs.gui.Actions() <- AddToBox{
		box: cs.vboxName,
		pos: index * 2,
		child: EventBox{
			widgetBase: widgetBase{name: c.boxName, background: c.background},
			child:      VBox{children: children},
		},
	}
	cs.gui.Signal()
}

func (cs *listUI) SetInsensitive(id uint64) {
	for i, entry := range cs.entries {
		if entry.id == id {
			cs.entries[i].insensitive = true
		}
	}
}

func (cs *listUI) Remove(id uint64) {
	newEntries := make([]listItem, 0, len(cs.entries))
	for i, entry := range cs.entries {
		if entry.id == id {
			if i > 0 {
				cs.gui.Actions() <- Destroy{name: entry.sepName}
			}
			cs.gui.Actions() <- Destroy{name: entry.boxName}
			cs.gui.Signal()
			if cs.selected == id {
				cs.selected = 0
			}
			continue
		}
		newEntries = append(newEntries, entry)
	}

	if len(newEntries) == len(cs.entries) {
		panic("unknown id passed to Remove")
	}
	cs.entries = newEntries
}

func (cs *listUI) Deselect() {
	if cs.selected == 0 {
		return
	}

	var currentlySelected *listItem

	for i, entry := range cs.entries {
		if entry.id == cs.selected {
			currentlySelected = &cs.entries[i]
			break
		}
	}

	cs.gui.Actions() <- SetBackground{name: currentlySelected.boxName, color: currentlySelected.background}
	cs.selected = 0
	cs.gui.Signal()
}

func (cs *listUI) Select(id uint64) {
	if id == cs.selected {
		return
	}

	var currentlySelected, newSelected *listItem

	for i, entry := range cs.entries {
		if entry.id == cs.selected {
			currentlySelected = &cs.entries[i]
		} else if entry.id == id {
			newSelected = &cs.entries[i]
		}

		if currentlySelected != nil && newSelected != nil {
			break
		}
	}

	if newSelected == nil {
		panic("internal error")
	}

	if currentlySelected != nil {
		cs.gui.Actions() <- SetBackground{name: currentlySelected.boxName, color: currentlySelected.background}
	}
	cs.gui.Actions() <- SetBackground{name: newSelected.boxName, color: colorHighlight}
	cs.selected = id
	cs.gui.Signal()
}

func (cs *listUI) SetIndicator(id uint64, indicator Indicator) {
	for _, entry := range cs.entries {
		if entry.id == id {
			cs.gui.Actions() <- SetImage{name: entry.imageName, image: indicator}
			cs.gui.Signal()
			break
		}
	}
}

func (cs *listUI) SetLine(id uint64, line string) {
	for _, entry := range cs.entries {
		if entry.id == id {
			cs.gui.Actions() <- SetText{name: entry.lineName, text: line}
			cs.gui.Signal()
			break
		}
	}
}

// SetSubline sets the second row of text in an entry.
func (cs *listUI) SetSubline(id uint64, subline string) {
	for i, entry := range cs.entries {
		if entry.id == id {
			if entry.hasSubline {
				if len(subline) > 0 {
					cs.gui.Actions() <- SetText{name: entry.sublineTextName, text: subline}
				} else {
					cs.gui.Actions() <- Destroy{name: entry.sublineTextName}
					cs.entries[i].hasSubline = false
				}
			} else if len(subline) > 0 {
				cs.gui.Actions() <- AddToBox{
					box:   entry.sublineBoxName,
					pos:   0,
					child: sublineLabel(entry.sublineTextName, subline),
				}
				cs.entries[i].hasSubline = true
			}
			cs.gui.Signal()
			break
		}
	}
}

func (cs *listUI) SetBackground(id uint64, color uint32) {
	for i, entry := range cs.entries {
		if entry.id == id {
			cs.entries[i].background = color
			if cs.selected != id {
				cs.gui.Actions() <- SetBackground{name: entry.boxName, color: color}
				cs.gui.Signal()
			}
			break
		}
	}
}

func (cs *listUI) newIdent() string {
	id := cs.vboxName + "-" + strconv.Itoa(cs.nextId)
	cs.nextId++
	return id
}
