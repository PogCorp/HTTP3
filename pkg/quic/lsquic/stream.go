package lsquic

/*
#cgo CFLAGS: -I ./boringssl/include -I ./include -I ./lsquic/include -I ./lsquic/src/liblsquic
#cgo LDFLAGS: -L${SRCDIR}/. -lev -lm -lz -lssl -lcrypto -llsquic -ladapter
#include <stdlib.h>
#include <stdbool.h>
#include "lsquic.h"
#include "adapter.h"
*/
import "C"
import (
	"log"
	adapter "poghttp3/pkg/quic"
	"unsafe"
)

type QuicBiStream struct {
	id             adapter.StreamId
	stream         *C.lsquic_stream_t
	sendBuffer     **C.char
	sendBufferSize *C.size_t
	sendBufferOff  *C.off_t
	// TODO: a mutex should probably be used that comes from the stream context
}

func (l *QuicBiStream) Close(reason adapter.ApplicationError) {
	// NOTE: Lsquic for some reason does not provide an api for canceling
	//		streams with application error as per 11.2 of RFC 9000
	ok := C.lsquic_stream_close(l.stream)
	if ok == 0 {
		return
	}
	log.Printf("could not close stream")
}

func (l *QuicBiStream) Write(p []byte) (n int, err error) {
	*l.sendBufferSize = (C.size_t)(len(p))
	*l.sendBufferOff = 0
	*l.sendBuffer = (*C.char)(unsafe.Pointer(&p[0]))
	C.lsquic_stream_wantwrite(l.stream, C.true)

	return len(p), nil
}

func (l *QuicBiStream) ID() adapter.StreamId {
	return l.id
}

func NewQuicBiStream(lsStream *C.lsquic_stream_t, streamCtx *C.lsquic_stream_ctx_t) adapter.QuicBiStream {

	id := adapter.StreamId(C.lsquic_stream_id(lsStream))

	return &QuicBiStream{
		id:             id,
		stream:         lsStream,
		sendBuffer:     &streamCtx.send_buffer,
		sendBufferSize: &streamCtx.send_buffer_size,
		sendBufferOff:  &streamCtx.send_buffer_off,
	}
}
