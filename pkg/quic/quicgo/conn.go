package quicgo

import (
	"log"
	adapter "poghttp3/pkg/quic"

	"github.com/quic-go/quic-go"
)

type QuicGoConn struct {
	cid  quic.ConnectionID
	conn quic.Connection
}

func NewQuicGoConn(connId quic.ConnectionID, conn quic.Connection) adapter.QuicConn {
	return &QuicGoConn{
		cid:  connId,
		conn: conn,
	}
}

func (qc *QuicGoConn) String() string {
	return qc.cid.String()
}

func (qc *QuicGoConn) CreateUniStream(streamType adapter.StreamType) (adapter.QuicUniStream, error) {
	qs, err := qc.conn.OpenUniStream()
	return NewUniStream(qs), err
}

func (qc *QuicGoConn) Close(reason adapter.ApplicationError) {
	err := qc.conn.CloseWithError(quic.ApplicationErrorCode(reason), "TODO: mapper to message")
	if err != nil {
		log.Printf("failed to close stream, err: %s", err)
	}
}

func (qc *QuicGoConn) LocalAddress() string {
	return qc.conn.LocalAddr().String()
}

func (qc *QuicGoConn) RemoteAddress() string {
	return qc.conn.RemoteAddr().String()
}
