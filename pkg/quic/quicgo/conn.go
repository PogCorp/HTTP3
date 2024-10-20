package quicgo

import (
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
	qc.conn.CloseWithError(quic.ApplicationErrorCode(reason), "TODO: mapper to message")
}
