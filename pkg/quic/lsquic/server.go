package lsquic

/*
#cgo CFLAGS: -I ./boringssl/include -I ./include -I ./lsquic/include -I ./lsquic/src/liblsquic
#cgo LDFLAGS: -L . -L ./boringssl/ssl -L ./boringssl/crypto -L ./lsquic/src/liblsquic -l ev -l m -l z -l lsquic -l lsquic_adapter -l crypto -l ssl
#include "lsquic_int_types.h"
#include "lsquic_util.h"
#include "lsquic.h"
#include "logger.h"
#include "server.h"
#include "adapter.c"
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"log"
	adapter "poghttp3/pkg/quic"
	"unsafe"

	gopointer "github.com/mattn/go-pointer"
)

type LsQuicServer struct {
	lsServer *C.Server
	quicApi  adapter.QuicAPI
}

func (l *LsQuicServer) Listen() error {
	_, err := C.server_listen(l.lsServer)
	if err != nil {
		return fmt.Errorf("got error while trying to listen, errno: %s", err)
	}
	return nil
}

func NewLsquicServer(uri, keyfile, certfile string, api adapter.QuicAPI) (adapter.QuicServer, error) {
	server := LsQuicServer{
		lsServer: (*C.Server)(C.malloc(C.sizeof_Server)),
		quicApi:  api,
	}
	streamCtx := gopointer.Save(server)
	cUri := C.CString(uri)
	defer C.free(unsafe.Pointer(cUri))
	cKeyfile := C.CString(keyfile)
	defer C.free(unsafe.Pointer(cKeyfile))
	cCertfile := C.CString(certfile)
	defer C.free(unsafe.Pointer(cCertfile))

	ok, err := C.new_server(server.lsServer, nil, &C.stream_interface, streamCtx)
	if !ok || err != nil {
		return nil, errors.New("unable to create new server")
	}

	proto := C.CString("echo")
	defer C.free(unsafe.Pointer(proto))
	C.server_add_alpn(server.lsServer, proto)
	if !ok {
		return nil, errors.New("proto could not be inserted")
	}
	ok = C.add_v_server(server.lsServer, cUri, cCertfile, cKeyfile)
	if !ok {
		return nil, errors.New("could not create v_server")
	}
	return &server, nil
}

// export adapterOnNewConnection
func adapterOnNewConnection(conn *C.lsquic_conn_t, streamIfCtx unsafe.Pointer) *C.lsquic_conn_ctx_t {
	sni := C.lsquic_conn_get_sni(conn)
	goSni := C.GoString(sni)
	server, ok := gopointer.Restore(streamIfCtx).(LsQuicServer)
	if !ok {
		panic("passed on the incorrect type")
	}
	lsQuicCid := NewLsquicCID(conn)
	server.quicApi.OnNewConnection(lsQuicCid)
	log.Printf("on sni: %s\n", goSni)
	connCtx := (*C.lsquic_conn_ctx_t)(C.malloc(C.sizeof_lsquic_conn_ctx_t))
	connCtx.adapter_ctx = streamIfCtx
	return connCtx
}

// export adapterOnClosedConnection
func adapterOnClosedConnection(conn *C.lsquic_conn_t) {
	connCtx := C.lsquic_conn_get_ctx(conn)
	lsQuicCid := NewLsquicCID(conn)
	server, ok := gopointer.Restore(connCtx.adapter_ctx).(LsQuicServer)
	if !ok {
		panic("passed on the incorrect type")
	}
	server.quicApi.OnCanceledConn(lsQuicCid)
}

// export adapterOnNewStream
func adapterOnNewStream(stream *C.lsquic_stream_t, streamCtx unsafe.Pointer) *C.lsquic_stream_ctx_t {
	id := C.lsquic_stream_id(stream)
	log.Printf("new stream with id: #%d\n", uint64(id))
	streamCtxOut := (*C.lsquic_stream_ctx_t)(C.malloc(C.sizeof_lsquic_stream_ctx_t))
	streamCtxOut.adapter_ctx = streamCtx
	streamCtxOut.send_buffer = nil
	streamCtxOut.send_buffer_size = 0
	streamCtxOut.send_buffer_off = 0
	return streamCtxOut

}

// export adapterOnWrite
func adapterOnWrite(stream *C.lsquic_stream_t, adapter_ctx unsafe.Pointer) {

}

// export adapterOnRead
func adapterOnRead(stream *C.lsquic_stream_t, buf *C.char, buf_size C.size_t, adapter_cxt unsafe.Pointer) {

}

// export adapterOnClose
func adapterOnClose(stream *C.lsquic_stream_t, streamCtx *C.lsquic_stream_ctx_t) {
	id := C.lsquic_stream_id(stream)
	log.Printf("closing stream with id: #%d\n", uint64(id))
	C.free(unsafe.Pointer(streamCtx))
}
