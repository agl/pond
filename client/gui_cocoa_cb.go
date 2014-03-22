package main

// #include <stdint.h>
// #include <stdlib.h>
// #include <string.h>
import "C"

import "syscall"
import "unsafe"
import "fmt"

//export incomingSignalCallback
func incomingSignalCallback(i *C.uint64_t, s **C.char, l *C.size_t) C.uint {
	var buf [1]byte
	syscall.Read(globalClient.signalReadFD, buf[:])

	cmd := <-globalClient.actions
	*i = C.uint64_t(cmd.i)
	*s = nil
	*l = 0
	if len(cmd.s) != 0 {
		*s = C.CString(cmd.s)
		*l = C.size_t(len(cmd.s))
	}
	return C.uint(cmd.cmd)
}

//export sendCocoaEvent
func sendCocoaEvent(event int, i C.uint64_t, s *C.uint8_t, sLength C.size_t) {
	var data []byte
	if sLength > 0 {
		data = make([]byte, sLength)
		C.memcpy(unsafe.Pointer(&data[0]), unsafe.Pointer(s), sLength)
	}
	globalClient.events <- cocoaEvent{uint(event), uint64(i), data}
	if sLength > 0 {
		C.free(unsafe.Pointer(s))
	}
}

//export randomHexSecret
func randomHexSecret() *C.char {
	var buf [16]byte
	globalClient.randBytes(buf[:])
	return C.CString(fmt.Sprintf("%x", buf[:]))
}
