package lsquic

/*
#cgo CFLAGS: -I ./boringssl/include -I ./include -I ./lsquic/include -I ./lsquic/src/liblsquic
#cgo LDFLAGS: -L . -L ./boringssl/ssl -L ./boringssl/crypto -L ./lsquic/src/liblsquic -l ev -l m -l z -l lsquic -l lsquic_adapter -l crypto -l ssl
#include "lsquic.h"
#include <stdlib.h>
#include <stdbool.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type LsQuicStream struct {
	lsStream       *C.lsquic_stream_t
	sendBuffer     **C.char
	sendBufferSize *C.size_t
	sendBufferOff  *C.off_t
}

func (l *LsQuicStream) Close() error {
	ok := C.lsquic_stream_close(l.lsStream)
	if ok == 0 {
		return nil
	}
	return fmt.Errorf("could not close stream")
}

func (l *LsQuicStream) Write(p []byte) (n int, err error) {
	if *l.sendBuffer != nil {
		C.free(unsafe.Pointer(l.sendBuffer))
	}
	*l.sendBufferSize = (C.size_t)(len(p))
	*l.sendBufferOff = 0
	*l.sendBuffer = (*C.char)(C.CBytes(p))
	C.lsquic_stream_wantwrite(l.lsStream, C.true)
	return len(p), nil
}
