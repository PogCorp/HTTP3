package lsquic

/*
#cgo CFLAGS: -I ./boringssl/include -I ./include -I ./lsquic/include -I ./lsquic/src/liblsquic
#cgo LDFLAGS: -L${SRCDIR}/. -ladapter -L${SRCDIR}/boringssl/ssl -lssl -L${SRCDIR}/boringssl/crypto -lcrypto -L${SRCDIR}/lsquic/src/liblsquic -llsquic -lev -lm -lz
#include "lsquic_int_types.h"
#include "lsquic_util.h"
#include "lsquic.h"
*/
import "C"

import adapter "poghttp3/pkg/quic"

type LsQuicCID struct {
	lsConn *C.lsquic_conn_t
}

func (l *LsQuicCID) String() string {
	cid := C.lsquic_conn_id(l.lsConn)
	cidString := [0x29]C.char{}
	C.lsquic_hexstr(&cid.buf[0], C.ulong(cid.len), &cidString[0], 0x29)
	return C.GoString(&cidString[0])
}

func NewLsquicCID(lsConn *C.lsquic_conn_t) adapter.QuicCID {
	return &LsQuicCID{
		lsConn: lsConn,
	}
}
