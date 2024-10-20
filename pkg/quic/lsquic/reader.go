package lsquic

/*
#cgo CFLAGS: -I ./boringssl/include -I ./include -I ./lsquic/include -I ./lsquic/src/liblsquic
#cgo LDFLAGS: -L${SRCDIR}/. -lev -lm -lz -lssl -lcrypto -llsquic -ladapter
#include <stdlib.h>
#include "lsquic.h"
*/
import "C"
import (
	"fmt"
	"io"
	"unsafe"
)

type StreamReader struct {
	receivedFin bool
	stream      *C.lsquic_stream_t
}

func (s *StreamReader) Read(p []byte) (n int, err error) {
	if s.receivedFin {
		return 0, io.EOF
	}
	dstLen := len(p)
	numRead := C.lsquic_stream_read(s.stream, unsafe.Pointer(&p[0]), C.ulong(dstLen))
	if numRead < 0 {
		C.lsquic_conn_abort(C.lsquic_stream_conn(s.stream))
		return 0, fmt.Errorf("failure in reading stream, connection aborted")
	}

	if numRead == 0 {
		s.receivedFin = true
		return 0, io.EOF
	}

	return int(numRead), nil
}

func NewStreamReader(stream *C.lsquic_stream_t) io.Reader {
	return &StreamReader{
		stream:      stream,
		receivedFin: false,
	}
}

var _ io.Reader = &StreamReader{}
