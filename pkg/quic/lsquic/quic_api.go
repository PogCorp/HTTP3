package lsquic

import (
	"io"
	"log"
	adapter "poghttp3/pkg/quic"
)

// TODO:

type QuicApi struct {
}

func (l *QuicApi) OnNewConnection(conn adapter.QuicConn) {
	log.Printf("Received ConnectionID: %s\n", conn.String())
}

func (l *QuicApi) OnCanceledConn(conn adapter.QuicConn) {
	log.Printf("Connection with connection id: %s was cancelled\n", conn.String())
}

func (l *QuicApi) OnNewBiStream(conn adapter.QuicConn, stream adapter.QuicBiStream) {
	log.Printf("received bidirectional stream, id: %d\n", stream.ID())
}

func (l *QuicApi) OnReadBiStream(conn adapter.QuicConn, stream adapter.QuicBiStream, reader io.Reader) {
	log.Println("adapter on read bidirectional stream")
	payload := make([]byte, 4096)
	_, err := reader.Read(payload)
	if err != nil && err != io.EOF {
		log.Printf("could not read bidirectional stream, err: %s\n", err)
		return
	}
	_, err = stream.Write(payload)
	if err != nil {
		stream.Close(0x01)
	}
}

func (l *QuicApi) OnNewUniStream(conn adapter.QuicConn, id adapter.StreamId) {
	// NOTE: it is not possible to use unidirectional streams on LSQUIC
}

func (l *QuicApi) OnReadUniStream(conn adapter.QuicConn, id adapter.StreamId, reader io.Reader) {
	// NOTE: it is not possible to use unidirectional streams on LSQUIC
}

func NewQuicApi() adapter.QuicAPI {
	return &QuicApi{}
}
