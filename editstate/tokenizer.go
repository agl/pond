package main

import (
	"bufio"
	"fmt"
	"io"
	"unicode"
)

type Tokenizer struct {
	in   *bufio.Reader
	Line int
}

func NewTokenizer(in io.Reader) *Tokenizer {
	return &Tokenizer{
		in:   bufio.NewReader(in),
		Line: 1,
	}
}

func (t *Tokenizer) Next() (string, error) {
	if err := t.eatWhitespace(); err != nil {
		return "", err
	}

	token, err := t.nextToken()
	if err != nil {
		return "", err
	}

	if token == "<<" {
		// Multiline literal
		if err := t.eatWhitespace(); err != nil {
			return "", err
		}
		delimToken, err := t.nextToken()
		if err != nil {
			return "", err
		}
		// Eat all whitespace up to a newline.
		for {
			r, _, err := t.in.ReadRune()
			if err != nil {
				return "", err
			}
			if r == '\n' {
				t.Line++
				break
			}
			if !unicode.IsSpace(r) {
				return "", fmt.Errorf("line %d: garbage after multiline delimiter", t.Line)
			}
		}

		// We only match the deliminator at the beginning of a line.
		delim := []rune("--" + delimToken)

		var literal []rune
		matched := 0
		for {
			r, _, err := t.in.ReadRune()
			if err != nil {
				return "", err
			}
			if r == '\n' {
				t.Line++
			}
			literal = append(literal, r)
			if r == delim[matched] {
				matched++
				if matched == len(delim) {
					return string(literal[:len(literal)-len(delim)]), nil
				}
			} else {
				matched = 0
				if r == delim[matched] {
					matched++
				}
			}
		}
	}

	return token, nil
}

func (t *Tokenizer) eatWhitespace() error {
	var isComment bool
	for {
		r, _, err := t.in.ReadRune()
		if err != nil {
			return err
		}
		switch {
		case r == '\n':
			t.Line++
			isComment = false
		case isComment:
			continue
		case unicode.IsSpace(r):
			continue
		case r == '#':
			isComment = true
		default:
			t.in.UnreadRune()
			return nil
		}
	}

	panic("unreachable")
}

func (t *Tokenizer) nextToken() (string, error) {
	var token []rune
	var firstIsSpecial, isQuote bool

	for {
		r, _, err := t.in.ReadRune()
		if err == io.EOF && len(token) != 0 {
			if isQuote {
				return "", fmt.Errorf("line %d: hit EOF in quoted string", t.Line)
			}
			return string(token), nil
		}
		if err != nil {
			return "", err
		}
		isSpecial := !unicode.IsDigit(r) && !unicode.IsLetter(r)
		isWhitespace := unicode.IsSpace(r)

		if len(token) == 0 {
			if isWhitespace && !isQuote {
				panic("impossible")
			}
			firstIsSpecial = isSpecial
			if r == '"' {
				if isQuote {
					// Empty quotes
					return "", nil
				}
				isQuote = true
				continue
			}
		}

		if isQuote {
			if r == '"' {
				return string(token), nil
			}
			if r == '\n' {
				return "", fmt.Errorf("line %d: new line in quoted string", t.Line)
			}
			if r == '\\' {
				r, _, err = t.in.ReadRune()
				if err != nil {
					return "", err
				}
			}
		} else if isWhitespace || firstIsSpecial != isSpecial {
			t.in.UnreadRune()
			return string(token), nil
		}

		token = append(token, r)
	}

	panic("unreachable")
}
