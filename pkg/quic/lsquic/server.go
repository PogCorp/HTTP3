package lsquic

/*
#cgo CFLAGS: -I ./boringssl/include -I ./include -I ./lsquic/include -I ./lsquic/src/liblsquic
#cgo LDFLAGS: -L${SRCDIR}/. -lev -lm -lz -lssl -lcrypto -llsquic -ladapter
#include "lsquic_int_types.h"
#include "lsquic_util.h"
#include "lsquic.h"
#include "logger.h"
#include "adapter.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>

extern lsquic_conn_ctx_t* server_on_new_connection(void* stream_if_ctx,
    struct lsquic_conn* conn);

extern void server_on_closed_connection(lsquic_conn_t* conn);

extern lsquic_stream_ctx_t* server_on_new_stream(void* stream_if_ctx,
    struct lsquic_stream* stream);

extern void server_on_read(struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx);

extern void server_on_write(struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx);

extern void server_on_close(struct lsquic_stream* stream,
    lsquic_stream_ctx_t* stream_ctx);
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
	streamIfCtx := gopointer.Save(server)
	cUri := C.CString(uri)
	defer C.free(unsafe.Pointer(cUri))
	cKeyfile := C.CString(keyfile)
	defer C.free(unsafe.Pointer(cKeyfile))
	cCertfile := C.CString(certfile)
	defer C.free(unsafe.Pointer(cCertfile))
	C.set_logger_fd(C.stdout)

	ok, err := C.lsquic_new_server(server.lsServer, nil, streamIfCtx)
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

//export adapterOnNewConnection
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

//export adapterOnClosedConnection
func adapterOnClosedConnection(conn *C.lsquic_conn_t) {
	connCtx := C.lsquic_conn_get_ctx(conn)
	lsQuicCid := NewLsquicCID(conn)
	server, ok := gopointer.Restore(connCtx.adapter_ctx).(LsQuicServer)
	if !ok {
		panic("passed on the incorrect type")
	}
	server.quicApi.OnCanceledConn(lsQuicCid)
	C.lsquic_conn_set_ctx(conn, nil)
}

//export adapterOnNewStream
func adapterOnNewStream(stream *C.lsquic_stream_t, streamIfCtx unsafe.Pointer) *C.lsquic_stream_ctx_t {
	id := C.lsquic_stream_id(stream)
	log.Printf("new stream with id: #%d\n", uint64(id))
	streamCtxOut := (*C.lsquic_stream_ctx_t)(C.malloc(C.sizeof_lsquic_stream_ctx_t))
	streamCtxOut.adapter_ctx = streamIfCtx
	streamCtxOut.send_buffer = nil
	streamCtxOut.send_buffer_size = 0
	streamCtxOut.send_buffer_off = 0
	C.lsquic_stream_wantread(stream, C.true)
	return streamCtxOut

}

//export adapterOnWrite
func adapterOnWrite(stream *C.lsquic_stream_t, streamCtx *C.lsquic_stream_ctx_t) {
	numWritten := C.lsquic_stream_write(stream, unsafe.Pointer(streamCtx.send_buffer), streamCtx.send_buffer_size)
	C.lsquic_stream_flush(stream)
	if numWritten < 0 {
		log.Println("failed to write to stream")
		return
	}
	streamCtx.send_buffer_off += numWritten
	server, ok := gopointer.Restore(streamCtx.adapter_ctx).(LsQuicServer)
	if !ok {
		panic("passed on the incorrect type")
	}
	lsStream := NewLsQuicStream(stream, streamCtx)
	server.quicApi.OnWriteStream(lsStream)
	C.lsquic_stream_wantread(stream, C.false)
	C.lsquic_stream_wantwrite(stream, C.false)
}

//export adapterOnRead
func adapterOnRead(stream *C.lsquic_stream_t, buf *C.char, bufSize C.size_t, streamCtx *C.lsquic_stream_ctx_t) {
	lsStream := NewLsQuicStream(stream, streamCtx)
	server, ok := gopointer.Restore(streamCtx.adapter_ctx).(LsQuicServer)
	if !ok {
		panic("passed on the incorrect type")
	}
	server.quicApi.OnWriteStream(lsStream)
	numRead := C.lsquic_stream_read(stream, unsafe.Pointer(buf), bufSize)
	if numRead < 0 {
		log.Println("failure in reading stream, aborting connection")
		C.lsquic_conn_abort(C.lsquic_stream_conn(stream))
	}
	rcvBuf := C.GoBytes(unsafe.Pointer(buf), C.int(numRead))
	log.Printf("received: '%s'\n", string(rcvBuf))
	_, err := lsStream.Write(rcvBuf)
	if err != nil {
		log.Println("failed to write bytes")
		return
	}
	C.lsquic_stream_wantread(stream, C.false)
}

//export adapterOnClose
func adapterOnClose(stream *C.lsquic_stream_t, streamCtx *C.lsquic_stream_ctx_t) {
	lsStream := NewLsQuicStream(stream, streamCtx)
	server, ok := gopointer.Restore(streamCtx.adapter_ctx).(LsQuicServer)
	if !ok {
		panic("passed on the incorrect type")
	}
	id := C.lsquic_stream_id(stream)
	server.quicApi.OnWriteStream(lsStream)
	log.Printf("closing stream with id: #%d\n", uint64(id))
	C.free(unsafe.Pointer(streamCtx))
}
