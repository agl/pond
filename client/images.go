package main

import (
	"strconv"
)

type Indicator int

const (
	indicatorNone Indicator = iota
	indicatorRed
	indicatorYellow
	indicatorGreen
	indicatorBlue
	indicatorBlack
	indicatorRemove
	indicatorAdd
	indicatorCount
)

func starWithColor(xtermColorNum int) string {
	return "\x1b[38;5;" + strconv.Itoa(xtermColorNum) + "m*\x1b[0m"
}

// Star returns a colored star for the given indicator
func (i Indicator) Star() string {
	switch i {
	case indicatorRed:
		return starWithColor(160)
	case indicatorYellow:
		return starWithColor(227)
	case indicatorGreen:
		return starWithColor(82)
	case indicatorBlue:
		return starWithColor(57)
	case indicatorBlack:
		return starWithColor(201)
	}

	return " "
}
