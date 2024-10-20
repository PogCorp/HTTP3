package main

import (
	"fmt"
	"io"
	"log"
	adapter "poghttp3/pkg/quic"
	"poghttp3/pkg/quic/quicgo"
)

type QuicGoAdapter struct {
}

func (q *QuicGoAdapter) OnNewUniStream(conn adapter.QuicConn, id adapter.StreamId) {
	fmt.Printf("Accepted unidirectional stream with id: %d\n", id)
}

func (q *QuicGoAdapter) OnReadUniStream(conn adapter.QuicConn, id adapter.StreamId, reader io.Reader) {
	payload, err := io.ReadAll(reader)
	if err != nil {
		fmt.Printf("could not read unidirectional stream, err: %s\n", err)
		return
	}
	fmt.Printf("Read unidirectional stream: %d with content: %s\n", id, string(payload))
}

func (q *QuicGoAdapter) OnNewBiStream(conn adapter.QuicConn, stream adapter.QuicBiStream) {
	fmt.Printf("Accepted bidirectional stream with id: %d\n", stream.ID())
}

func (q *QuicGoAdapter) OnReadBiStream(conn adapter.QuicConn, stream adapter.QuicBiStream, reader io.Reader) {
	payload := make([]byte, 4096)
	_, err := reader.Read(payload)
	if err != nil && err != io.EOF {
		fmt.Printf("could not read bidirectional stream, err: %s\n", err)
		return
	}
	fmt.Printf("Read bidirectional stream: %d with content: %s\n", stream.ID(), string(payload))
	_, err = stream.Write(payload)
	if err != nil {
		fmt.Printf("could not send, err: %s\n", err)
	}
	stream.Close(0x0)
}

func (q *QuicGoAdapter) OnCanceledConn(conn adapter.QuicConn) {
	fmt.Printf("Connection with connection id: %s was cancelled\n", conn.String())
}

func (q *QuicGoAdapter) OnNewConnection(conn adapter.QuicConn) {
	fmt.Printf("Received ConnectionID: %s\n", conn.String())
}

func NewQuicGoAdapter() adapter.QuicAPI {
	return &QuicGoAdapter{}
}

func main() {
	server, err := quicgo.NewQuicGoServer("localhost:8080", "../../certs/priv.key", "../../certs/cert.crt", NewQuicGoAdapter())
	if err != nil {
		log.Printf("could not create quicgo server, err: %s\n", err)
		return
	}
	if err := server.Listen(); err != nil {
		log.Printf("unable to listen, err: %s\n", err)
		return
	}
}
