package lsquic

import adapter "poghttp3/pkg/quic"

// TODO:

type LsQuicApi struct {
}

func (l *LsQuicApi) OnNewConnection(conn adapter.QuicCID) {

}

func (l *LsQuicApi) OnCanceledConn(conn adapter.QuicCID) {

}

func (l *LsQuicApi) OnNewStream(stream adapter.QuicStream) {

}

func (l *LsQuicApi) OnWriteStream(stream adapter.QuicStream) {

}

func (l *LsQuicApi) OnReadStream(stream adapter.QuicStream, data []byte) {

}

func NewLsQuicApi() adapter.QuicAPI {
	return &LsQuicApi{}
}
