package adapter

import (
	"context"
	"io"
)

type QuicAdapter interface {
	OnNewConnection(conn Connection)
	OnCancelledConnection(conn Connection)
	Listen() error
}

type Connection interface {
	AcceptStream(ctx context.Context) (Stream, error)

	// TODO: map all error codes and create enum
	CloseWithError(applicationErrorCode uint64, errorMessage string) error
	ConnectionID() string

	OnNewStream(stream Stream)
	OnReadStream(stream Stream) ([]byte, error)
	OnWriteStream(stream Stream, payload []byte) error
}

type Stream interface {
	io.Reader
	io.Writer
	io.Closer
}
