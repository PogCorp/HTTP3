package adapter

import (
	"fmt"
	"io"
)

type StreamType int8
type ApplicationError int64
type StreamId int64

type QuicServer interface {
	Listen() error
}

type QuicAPI interface {
	// TODO: there might be a use for contexts here
	OnNewConnection(conn QuicConn)
	OnCanceledConn(conn QuicConn)
	OnNewBiStream(conn QuicConn, stream QuicBiStream)
	OnReadBiStream(conn QuicConn, stream QuicBiStream, data io.Reader)
	OnNewUniStream(conn QuicConn, id StreamId)
	OnReadUniStream(conn QuicConn, id StreamId, data io.Reader)
}

// Streams can send data
type QuicBiStream interface {
	QuicUniStream
	Close(reason ApplicationError)
}

type QuicUniStream interface {
	io.Writer
	ID() StreamId
}

type QuicConn interface {
	fmt.Stringer
	Close(reason ApplicationError)
	CreateUniStream(streamType StreamType) (QuicUniStream, error)
	// NOTE: a more complete API could include the creation of Bidirectional Streams
}
