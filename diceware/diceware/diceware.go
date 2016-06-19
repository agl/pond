package main

import (
	"fmt"
	"crypto/rand"
	"github.com/agl/pond/diceware"
)

func main() {
	fmt.Println(diceware.DicewareWords(rand.Reader," ",6))
}

