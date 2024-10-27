package quicgo

import (
	adapter "poghttp3/pkg/quic"

	"github.com/quic-go/quic-go"
)

// ======================= BIDIRECTIONAL STREAMS =======================

type quicBiStream struct {
	stream quic.Stream
}

func NewBiStream(stream quic.Stream) adapter.QuicBiStream {
	return &quicBiStream{
		stream: stream,
	}
}

func (qs *quicBiStream) ID() adapter.StreamId {
	return adapter.StreamId(qs.stream.StreamID())
}

func (qs *quicBiStream) Write(p []byte) (n int, err error) {
	return qs.stream.Write(p)
}

// TODO: write function WriteFin to signal the end of writting on the stream
func (qs *quicBiStream) WriteFin() {
	qs.stream.Close()
}

// TODO: differentiate Cancel Read and Cancel Write
func (qs *quicBiStream) Close(reason adapter.ApplicationError) {
	qs.stream.CancelRead(quic.StreamErrorCode(reason))
	qs.stream.CancelWrite(quic.StreamErrorCode(reason))
}

// ======================= UNIDIRECTIONAL STREAMS =======================

type quicUniStream struct {
	stream quic.SendStream
}

func NewUniStream(stream quic.SendStream) adapter.QuicUniStream {
	return &quicUniStream{
		stream: stream,
	}
}

func (qs *quicUniStream) ID() adapter.StreamId {
	return adapter.StreamId(qs.stream.StreamID())
}

func (qs *quicUniStream) Write(p []byte) (n int, err error) {
	return qs.stream.Write(p)
}
