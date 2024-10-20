package lsquic

import adapter "poghttp3/pkg/quic"

// TODO:

type LsQuicApi struct {
}

func (l *LsQuicApi) OnNewConnection(conn adapter.QuicConn) {

}

func (l *LsQuicApi) OnCanceledConn(conn adapter.QuicConn) {

}

func (l *LsQuicApi) OnNewBiStream(conn adapter.QuicConn, stream adapter.QuicBiStream) {

}

func (l *LsQuicApi) OnReadBiStream(conn adapter.QuicConn, stream adapter.QuicBiStream, rcvData []byte) {

}

func (l *LsQuicApi) OnNewUniStream(conn adapter.QuicConn, id adapter.StreamId) {
	// NOTE: it is not possible to use unidirectional streams on LSQUIC
}

func (l *LsQuicApi) OnReadUniStream(conn adapter.QuicConn, id adapter.StreamId, rcvData []byte) {
	// NOTE: it is not possible to use unidirectional streams on LSQUIC
}

func NewLsQuicApi() adapter.QuicAPI {
	return &LsQuicApi{}
}
