package quicgo

import (
	adapter "poghttp3/pkg/quic"

	"github.com/quic-go/quic-go"
)

type quicStream struct {
	stream quic.Stream
}

func NewStream(stream quic.Stream) adapter.QuicStream {
	return &quicStream{
		stream: stream,
	}
}

func (qs *quicStream) ID() uint64 {
	return uint64(qs.stream.StreamID())
}

func (qs *quicStream) Write(p []byte) (n int, err error) {
	return qs.stream.Write(p)
}

func (qs *quicStream) Close() error {
	return qs.stream.Close()
}
