package lsquic

/*
#cgo CFLAGS: -I ./boringssl/include -I ./include -I ./lsquic/include -I ./lsquic/src/liblsquic
#cgo LDFLAGS: -L${SRCDIR}/. -lev -lm -lz -lssl -lcrypto -llsquic
#include "lsquic_int_types.h"
#include "lsquic_util.h"
#include "lsquic.h"
*/
import "C"

import (
	"fmt"
	adapter "poghttp3/pkg/quic"
)

type QuicConn struct {
	lsConn *C.lsquic_conn_t
}

func (l *QuicConn) String() string {
	cid := C.lsquic_conn_id(l.lsConn)
	cidString := [0x29]C.char{}
	C.lsquic_hexstr(&cid.buf[0], C.ulong(cid.len), &cidString[0], 0x29)
	return C.GoString(&cidString[0])
}

func (l *QuicConn) CreateUniStream(streamType adapter.StreamType) (adapter.QuicUniStream, error) {
	// NOTE: LSQUIC does not implement the creation of unidirectional streams.
	//		Thought there is the function create_uni_stream_out for this
	//		it is not accessible for the library user, and the client can
	//		only use lsquic_conn_make_stream that creates a bidirectional
	//		stream.
	//
	//		The addition of such a feature is indeed possible, but a fork of
	//		the project is needed.
	//		The following steps can be taken for the addition:
	//			- add a function in the struct conn_iface that receives a
	//			  conn and creates a unidirectional stream
	//			- this new function needs to receive a connection and return a
	//			  lsquic_stream.
	//			- use create_uni_stream_out instead of create_bidi_stream_out in a
	//			  similar fashion as in ietf_full_conn_ci_make_stream
	//			- add in the files lsquic_conn.h and lsquic_conn.c a new function
	//			  that calls the conn_iface function for creating unidirectional
	//			  streams.
	return nil, fmt.Errorf("lsquic does not support creation of unidirectional streams")
}

func (l *QuicConn) Close(reason adapter.ApplicationError) {
	// NOTE: Again, there is no way to informe the reason of why this connection is being
	//		closed
	C.lsquic_conn_close(l.lsConn)
}

func (qc *QuicConn) LocalAddress() string {
	return ""
}

func (qc *QuicConn) RemoteAddress() string {
	// somehow lsquic does not provide an api to access this
	// even though there is lsquic_conn_get_sockaddr, the returned
	// data is aways broken
	return ""
}

func NewQuicConn(lsConn *C.lsquic_conn_t) adapter.QuicConn {
	return &QuicConn{
		lsConn: lsConn,
	}
}
