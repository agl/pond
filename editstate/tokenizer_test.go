package main

import (
	"bytes"
	"io"
	"testing"
)

var tokenizerTests = []struct {
	in  string
	out []string
}{
	{"foo", []string{"foo"}},
	{"foo \" \"", []string{"foo", " "}},
	{"foo \"\"", []string{"foo", ""}},
	{"foo:", []string{"foo", ":"}},
	{"foo: bar\n", []string{"foo", ":", "bar"}},
	{"foo: bar\n", []string{"foo", ":", "bar"}},
	{"foo: bar\nbaz", []string{"foo", ":", "bar", "baz"}},
	{"foo: \"bar baz\"", []string{"foo", ":", "bar baz"}},
	{`foo: <<delim
--delim`, []string{"foo", ":", ""}},
	{`foo: <<delim

--delim`, []string{"foo", ":", "\n"}},
	{`foo: <<delim
wibble
wobble
--delim
`, []string{"foo", ":", "wibble\nwobble\n"}},
	{`foo # comment to end of line\n
bar
# boo
baz`, []string{"foo", "bar", "baz"}},
}

func TestTokenizer(t *testing.T) {
NextTest:
	for i, test := range tokenizerTests {
		tokenizer := NewTokenizer(bytes.NewBufferString(test.in))
		for j, expected := range test.out {
			token, err := tokenizer.Next()
			if err != nil {
				t.Errorf("%d: error while reading token %d: %s", i, j, err)
				continue NextTest
			}
			if token != expected {
				t.Errorf("%d: got '%s' as token %d, want '%s'", i, token, j, expected)
				continue NextTest
			}
		}
		if token, err := tokenizer.Next(); err != io.EOF {
			t.Errorf("%d: didn't get EOF after last token, rather got: %s %s", i, token, err)
		}
	}
}
