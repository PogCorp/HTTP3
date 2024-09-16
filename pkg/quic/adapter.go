package adapter

import (
	"fmt"
	"io"
)

type QuicServer interface {
	Listen() error
}

type QuicAPI interface {
	OnNewConnection(cid QuicCID)
	OnCanceledConn(cid QuicCID)
	OnNewStream(stream QuicStream)
	OnReadStream(stream QuicStream, data []byte)
	OnWriteStream(stream QuicStream)
}

type QuicStream interface {
	io.WriteCloser
}

type QuicCID interface {
	fmt.Stringer
}
