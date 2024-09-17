package lsquic

/*
#cgo CFLAGS: -I ./boringssl/include -I ./include -I ./lsquic/include -I ./lsquic/src/liblsquic
#cgo LDFLAGS: -L${SRCDIR}/. -ladapter -L${SRCDIR}/boringssl/ssl -lssl -L${SRCDIR}/boringssl/crypto -lcrypto -L${SRCDIR}/lsquic/src/liblsquic -llsquic -lev -lm -lz
#include <stdlib.h>
#include <stdbool.h>
#include "lsquic.h"
#include "adapter.h"
*/
import "C"
import (
	"fmt"
	adapter "poghttp3/pkg/quic"
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

func (l *LsQuicStream) ID() uint64 {
	id := C.lsquic_stream_id(l.lsStream)
	return uint64(id)
}

func NewLsQuicStream(lsStream *C.lsquic_stream_t, streamCtx *C.lsquic_stream_ctx_t) adapter.QuicStream {
	return &LsQuicStream{
		lsStream:       lsStream,
		sendBuffer:     &streamCtx.send_buffer,
		sendBufferSize: &streamCtx.send_buffer_size,
		sendBufferOff:  &streamCtx.send_buffer_off,
	}
}
