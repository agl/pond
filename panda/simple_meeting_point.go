package panda

import (
	"bytes"
	"errors"
	"sync"
)

const paddingSize = 1 << 16

type pair struct {
	messages [2][]byte
}

type SimpleMeetingPlace struct {
	sync.Mutex
	values                 map[string]*pair
	wakeChan chan bool
}

func (smp *SimpleMeetingPlace) Padding() int {
	return paddingSize
}

func (smp *SimpleMeetingPlace) Exchange(log func(string, ...interface{}), id, message []byte, shutdown chan struct{}) ([]byte, error) {
	i := string(id)

	smp.Lock()

	var p *pair
	if p = smp.values[i]; p == nil {
		p = new(pair)
		smp.values[i] = p
		p.messages[0] = message
	}

	for i := 0; i < 2; i++ {
		if len(p.messages[i]) == 0 || bytes.Equal(p.messages[i], message) {
			if len(p.messages[i]) == 0 {
				p.messages[i] = message
				select {
				case smp.wakeChan <- true:
				default:
				}
			}
			for {
				other := p.messages[i^1]
				if len(other) > 0 {
					smp.Unlock()
					return other, nil
				}
				smp.Unlock()
				select {
				case <-smp.wakeChan:
					smp.Lock()
				case <-shutdown:
					return nil, ShutdownErr
				}
			}
		}
	}

	return nil, errors.New("more than two messages for a single id")
}

func NewSimpleMeetingPlace() *SimpleMeetingPlace {
	s := &SimpleMeetingPlace{
		values:       make(map[string]*pair),
		wakeChan:     make(chan bool),
	}
	return s
}
