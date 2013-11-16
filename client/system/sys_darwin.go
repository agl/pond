package system

// #include <stdlib.h>
// #include <string.h>
// #include <mach-o/dyld.h>
import "C"

import "unsafe"

func GetExecutablePath() string {
	var bufSize C.uint32_t
	C._NSGetExecutablePath(nil, &bufSize)
	
	buf := (*C.char)(C.malloc(C.size_t(bufSize+1)))
	C.memset(unsafe.Pointer(buf), 0, C.size_t(bufSize+1))
	C._NSGetExecutablePath(buf, &bufSize)
	ret := C.GoString(buf)
	C.free(unsafe.Pointer(buf))
	return ret
}
