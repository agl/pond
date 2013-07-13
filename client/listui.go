package main

import (
	"strconv"
)

// listUI manages the sections in the left-hand side list. It contains a number
// of items, which may have subheadlines and indicators (coloured dots).
type listUI struct {
	ui       UI
	vboxName string
	entries  []listItem
	selected uint64
	nextId   int
}

type listItem struct {
	id                                                           uint64
	name, sepName, boxName, imageName, lineName, sublineTextName string
	insensitive                                                  bool
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

func (cs *listUI) Add(id uint64, name, subline string, indicator Indicator) {
	c := listItem{
		id:              id,
		name:            name,
		sepName:         cs.newIdent(),
		boxName:         cs.newIdent(),
		imageName:       cs.newIdent(),
		lineName:        cs.newIdent(),
		sublineTextName: cs.newIdent(),
	}
	cs.entries = append(cs.entries, c)
	index := len(cs.entries) - 1

	if index > 0 {
		// Add the separator bar.
		cs.ui.Actions() <- AddToBox{
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
		sublineChildren = append(sublineChildren, Label{
			widgetBase: widgetBase{
				padding:    5,
				foreground: colorSubline,
				font:       fontListSubline,
				name:       c.sublineTextName,
			},
			text: subline,
		})
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
		widgetBase: widgetBase{padding: 1},
		children:   sublineChildren,
	})

	cs.ui.Actions() <- AddToBox{
		box: cs.vboxName,
		pos: index * 2,
		child: EventBox{
			widgetBase: widgetBase{name: c.boxName, background: colorGray},
			child:      VBox{children: children},
		},
	}
	cs.ui.Signal()
}

func (cs *listUI) SetInsensitive(id uint64) {
	for i, entry := range cs.entries {
		if entry.id == id {
			cs.entries[i].insensitive = true
		}
	}
}

func (cs *listUI) Remove(id uint64) {
	for i, entry := range cs.entries {
		if entry.id == id {
			if i > 0 {
				cs.ui.Actions() <- Destroy{name: entry.sepName}
			}
			cs.ui.Actions() <- Destroy{name: entry.boxName}
			cs.ui.Signal()
			if cs.selected == id {
				cs.selected = 0
			}
			return
		}
	}

	panic("unknown id passed to Remove")
}

func (cs *listUI) Deselect() {
	if cs.selected == 0 {
		return
	}

	var currentlySelected string

	for _, entry := range cs.entries {
		if entry.id == cs.selected {
			currentlySelected = entry.boxName
			break
		}
	}

	cs.ui.Actions() <- SetBackground{name: currentlySelected, color: colorGray}
	cs.selected = 0
	cs.ui.Signal()
}

func (cs *listUI) Select(id uint64) {
	if id == cs.selected {
		return
	}

	var currentlySelected, newSelected string

	for _, entry := range cs.entries {
		if entry.id == cs.selected {
			currentlySelected = entry.boxName
		} else if entry.id == id {
			newSelected = entry.boxName
		}

		if len(currentlySelected) > 0 && len(newSelected) > 0 {
			break
		}
	}

	if len(newSelected) == 0 {
		panic("internal error")
	}

	if len(currentlySelected) > 0 {
		cs.ui.Actions() <- SetBackground{name: currentlySelected, color: colorGray}
	}
	cs.ui.Actions() <- SetBackground{name: newSelected, color: colorHighlight}
	cs.selected = id
	cs.ui.Signal()
}

func (cs *listUI) SetIndicator(id uint64, indicator Indicator) {
	for _, entry := range cs.entries {
		if entry.id == id {
			cs.ui.Actions() <- SetImage{name: entry.imageName, image: indicator}
			cs.ui.Signal()
			break
		}
	}
}

func (cs *listUI) SetLine(id uint64, line string) {
	for _, entry := range cs.entries {
		if entry.id == id {
			cs.ui.Actions() <- SetText{name: entry.lineName, text: line}
			cs.ui.Signal()
			break
		}
	}
}

func (cs *listUI) SetSubline(id uint64, subline string) {
	for _, entry := range cs.entries {
		if entry.id == id {
			if len(subline) > 0 {
				cs.ui.Actions() <- SetText{name: entry.sublineTextName, text: subline}
			} else {
				cs.ui.Actions() <- Destroy{name: entry.sublineTextName}
			}
			cs.ui.Signal()
			break
		}
	}
}

func (cs *listUI) newIdent() string {
	id := cs.vboxName + "-" + strconv.Itoa(cs.nextId)
	cs.nextId++
	return id
}
