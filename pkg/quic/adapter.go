package adapter

import (
	"context"
	"io"
)

type QuickServer interface {
	Listen() error
}

type QuicAdapter interface {
	OnReadStream(streamID int64, data []byte)
	OnNewStream(streamID int64)
	OnNewConnection(connectionID string)
	OnCancelledConnection(connectionID string)
}

type QuickStream interface {
	io.Writer
	io.Closer
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
