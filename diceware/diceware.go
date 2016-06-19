package diceware

import (
	"io"
	"math/big"
	"crypto/rand"
	"strings"
)

func DicewareWords(r io.Reader, delim string, count int) string {
	l := big.NewInt(int64( len(diceware_words) ));
	words := []string{}
	for i := 0; i < count; i++ {
		j,err := rand.Int(r,l)
		if err != nil {
			panic("error reading from rand: " + err.Error())
		}
		words = append(words, diceware_words[j.Int64()])
	}
	return strings.Join(words, delim)
}

