package panda

import (
	"strconv"
)

// Suit represents one of the four suits in a standard deck of cards.
type Suit int

const (
	SuitSpades Suit = iota
	SuitHearts
	SuitDimonds
	SuitClubs
)

const (
	maxFace  = 13
	numCards = 4 * maxFace
)

// Card represents a playing card (except for the jokers).
type Card struct {
	face  int
	suit Suit
}

// String converts a Card to a two-glyph, string representation where the
// second glyph is a code-point for the suit.
func (c Card) String() string {
	var ret string

	switch c.face {
	case 1:
		ret = "A"
	case 2, 3, 4, 5, 6, 7, 8, 9, 10:
		ret = strconv.Itoa(c.face)
	case 11:
		ret = "J"
	case 12:
		ret = "Q"
	case 13:
		ret = "K"
	default:
		ret = "?"
	}

	switch c.suit {
	case SuitSpades:
		ret += "♠"
	case SuitHearts:
		ret += "♥"
	case SuitDimonds:
		ret += "♦"
	case SuitClubs:
		ret += "♣"
	}

	return ret
}

func (c Card) IsRed() bool {
	return c.suit == SuitDimonds || c.suit == SuitHearts
}

func (c Card) Number() int {
	return maxFace*int(c.suit) + (c.face - 1)
}

// ParseCard parses a card from a simple, two or three character string
// representation where the first character specifies the face value as one of
// "a23456789jqk" and the second the suit as one of "shdc". Case is ignored.
// The 10 is the exception and takes three charactors.
func ParseCard(s string) (card Card, ok bool) {
	var suitRune uint8

	switch len(s) {
	case 2:
		switch s[0] {
		case 'a', 'A':
			card.face = 1
		case '2', '3', '4', '5', '6', '7', '8', '9':
			card.face, _ = strconv.Atoi(s[:1])
		case 'j', 'J':
			card.face = 11
		case 'q', 'Q':
			card.face = 12
		case 'k', 'K':
			card.face = 13
		default:
			return
		}
		suitRune = s[1]
	case 3:
		if s[:2] != "10" {
			return
		}
		card.face = 10
		suitRune = s[2]
	default:
		return
	}

	switch suitRune {
	case 's', 'S':
		card.suit = SuitSpades
	case 'h', 'H':
		card.suit = SuitHearts
	case 'd', 'D':
		card.suit = SuitDimonds
	case 'c', 'C':
		card.suit = SuitClubs
	default:
		return
	}

	return card, true
}

type CardStack struct {
	NumDecks int
	counts   [numCards]int32
	minDecks int32
}

func (cs *CardStack) Add(c Card) bool {
	n := c.Number()
	if cs.counts[n] < int32(cs.NumDecks) {
		cs.counts[n]++
		if c := cs.counts[n]; c > cs.minDecks {
			cs.minDecks = c
		}
		return true
	}
	return false
}

func (cs *CardStack) Remove(c Card) bool {
	n := c.Number()
	if cs.counts[n] > 0 {
		cs.counts[n]--
		if cs.counts[n] == cs.minDecks-1 {
			// It's possible that, by removing this card, the
			// minimum number of decks has changed.
			max := int32(0)
			for _, c := range cs.counts {
				if c > max {
					max = c
				}
			}
			cs.minDecks = max
		}
		return true
	}
	return false
}

func (cs *CardStack) MinimumDecks() int {
	return int(cs.minDecks)
}

func (cs *CardStack) Canonicalise() *CardStack {
	// When a stack, consisting of one or more decks, is split in half,
	// there is a unique canonicalisation, defined as the half with the
	// majority of the lowest value card. For example, the one of spades is
	// the lowest value card and so, if the stack consists of a single
	// deck, then the half with the one of spades is the canonical one. If
	// the stack contains an even number of decks then it's possible to
	// have a draw. In this case, the next lowest value card is considered.
	// If all card values were split evenly between the two halves then the
	// two halves themselves are equal and so both are canonical.

	numDecks := int32(cs.NumDecks)
	upperThreshold := numDecks/2 + 1
	lowerThreshold := numDecks - upperThreshold
	for _, count := range cs.counts {
		if count >= upperThreshold {
			return cs
		} else if count <= lowerThreshold {
			ret := &CardStack{
				NumDecks: cs.NumDecks,
			}
			for i, count := range cs.counts {
				ret.counts[i] = numDecks - count
			}
			return ret
		}
	}

	return cs
}
