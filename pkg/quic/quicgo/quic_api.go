package quicgo

import (
	"fmt"
	adapter "poghttp3/pkg/quic"
)

type QuicGoAdapter struct {
	Streams map[int64]adapter.QuicStream
}

func (q *QuicGoAdapter) OnNewStream(stream adapter.QuicStream) {
	fmt.Printf("Accepted stream with id: %d\n", stream.ID())
}

func (q *QuicGoAdapter) OnReadStream(stream adapter.QuicStream, data []byte) {
	fmt.Printf("Read stream: %d with content: %s\n", stream.ID(), string(data))
}

func (q *QuicGoAdapter) OnCanceledConn(cid adapter.QuicCID) {
	fmt.Printf("Connection with connection id: %s was cancelled\n", cid.String())
}

func (q *QuicGoAdapter) OnNewConnection(cid adapter.QuicCID) {
	fmt.Printf("Received ConnectionID: %s\n", cid.String())
}

func (q *QuicGoAdapter) OnWriteStream(stream adapter.QuicStream) {
	fmt.Printf("Received ConnectionID: %d\n", stream.ID())
}

func NewQuicGoAdapter() adapter.QuicAPI {
	return &QuicGoAdapter{
		Streams: make(map[int64]adapter.QuicStream),
	}
}
