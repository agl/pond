// pathrewrite is a hacky utility for rewriting OS X shared libraries.
//
// On OS X we require that the Pond client be self-contained in a bundle directory. However, this means that the built-in paths in GTK etc need to be overridden so as to point inside the bundle. Sometimes this is possible via environment variables but sometimes there's just no way. Because of that, we process each shared library in the bundle with this problem which rewrites homebrew paths to be relative to the current working directory.

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <library file to rewrite>\n", os.Args[0])
		os.Exit(1)
	}

	contents, err := ioutil.ReadFile(os.Args[1])
	orig := contents
	if err != nil {
		fmt.Printf("Error opening input: %s\n", err)
		os.Exit(1)
	}

	// magic is the homebrew prefix that we look for.
	magic := []byte("/usr/local/Cellar/")
	// replacementPath is the path that replaces |magic|, plus a couple more path elements.
	replacementPath := []byte("../Resources")

NextMatch:
	for {
		i := bytes.Index(contents, magic)
		if i == -1 {
			break
		}

		s := contents[i:]
		contents = contents[i+1:]
		if len(s) > 256 {
			s = s[:256]
		}
		i = bytes.IndexByte(s, 0)
		if i == -1 {
			continue
		}
		s = s[:i]
		// After finding |magic|, we look for a path element that should be the name of the homebrew package.
		for i = len(magic); i < len(s); i++ {
			c := s[i]
			if c == '/' {
				break
			} else if (c >= 'a' && c <= 'z') || c == '+' || c == '-' || (c >= '0' && c <= '9') {
				continue
			} else {
				continue NextMatch
			}
		}
		if i == len(s) {
			continue
		}
		// After the package name, there should be a version.
		for i++; i < len(s); i++ {
			c := s[i]
			if c == '/' {
				break
			} else if (c >= '0' && c <= '9') || c == '.' {
				continue
			} else {
				continue NextMatch
			}
		}

		trailer := s[i:]
		var newPath []byte
		newPath = append(newPath, replacementPath...)
		newPath = append(newPath, trailer...)
		fmt.Printf("%s -> %s\n", string(s), string(newPath))
		newPath = append(newPath, 0)
		copy(s, newPath)
	}

	if err := ioutil.WriteFile(os.Args[1], orig, 0644); err != nil {
		fmt.Printf("Error writing file: %s\n", err)
		os.Exit(1)
	}
}
