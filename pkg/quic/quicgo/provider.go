package quicgo

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
	"log"
	"os"
	"path/filepath"
	adapter "poghttp3/pkg/quic"
	"time"
)

// const addr = "localhost:4242"

type QuicGoAdapter struct {
	Streams   map[int64]adapter.QuicStream
	TLSConfig *tls.Config
}

func NewQuicGoAdapter() adapter.QuicAdapter {
	return &QuicGoAdapter{
		Streams: make(map[int64]adapter.QuicStream),
	}
}

type quickServer struct {
	adapter   adapter.QuicAdapter
	tlsConfig *tls.Config
	address   string
}

func NewQuickGoServer(address string, tlsConfig *tls.Config, adapter adapter.QuicAdapter) adapter.QuicServer {
	return &quickServer{
		adapter:   adapter,
		tlsConfig: tlsConfig,
		address:   address,
	}
}

func (q *quickServer) Listen() error {
	qlogFilename := fmt.Sprintf("server_%s.qlog", time.Now().Format("20060102_150405"))
	qlogFile, err := os.Create(filepath.Join(".", qlogFilename))
	if err != nil {
		return fmt.Errorf("failed to create qlog file: %v", err)
	}
	defer qlogFile.Close()

	config := &quic.Config{
		EnableDatagrams: true,
		Tracer: func(ctx context.Context, p logging.Perspective, ci quic.ConnectionID) *logging.ConnectionTracer {
			//q.ConnectionIdChan <- ci.String()
			q.adapter.OnNewConnection(ci.String())
			return qlog.NewConnectionTracer(qlogFile, p, ci)
		},
		MaxIdleTimeout: time.Minute * 30,
	}

	listener, err := quic.ListenAddr(q.address, q.tlsConfig, config)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		ctx := context.Background()
		conn, err := listener.Accept(ctx)
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go q.handleConnection(ctx, conn)
	}
}

func (q *QuicGoAdapter) OnNewStream(streamID int64) {
	fmt.Printf("Accepted stream with id: %d\n", streamID)
}

func (q *QuicGoAdapter) OnReadStream(streamID int64, data []byte) {
	fmt.Printf("Read stream: %d with content: %s\n", streamID, string(data))
}

func (q *QuicGoAdapter) OnCancelledConnection(connectionID string) {
	fmt.Printf("Connection with connection id: %s was cancelled\n", connectionID)
}

func (q *QuicGoAdapter) OnNewConnection(connectionID string) {
	fmt.Printf("Received ConnectionID: %s\n", connectionID)

}

func (q *quickServer) handleConnection(ctx context.Context, conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			//log.Printf("Failed to accept stream: %v", err)
			// TODO: what to do when error
			return
		}
		q.adapter.OnNewStream(int64(stream.StreamID()))
		go q.handleStream(ctx, stream)
	}
}

func (q *quickServer) handleStream(ctx context.Context, stream quic.Stream) {
	defer stream.Close()
	streamID := int64(stream.StreamID())
	q.adapter.OnNewStream(streamID)

	buf := make([]byte, 4096)

	if _, err := stream.Read(buf); err != nil {
		log.Printf("Failed to read from stream: %v", err)
		return
	}

	fmt.Printf("Received DATA: %s\n", string(buf))
	q.adapter.OnReadStream(streamID, buf)
	q.simpleWrite("This is a response from server", stream)
}

func (q *quickServer) simpleWrite(data string, stream quic.Stream) {
	if _, err := stream.Write([]byte(data)); err != nil {
		log.Printf("Failed to write to stream: %v", err)
		return
	}

	fmt.Printf("Server sent: '%s'\n", data)
}

type quicConnection struct {
	conn         quic.Connection
	connectionID string
}

func NewConnection(conn quic.Connection, connectionID string) adapter.Connection {
	return &quicConnection{
		conn:         conn,
		connectionID: connectionID,
	}
}

func (qc *quicConnection) OnReadStream(stream adapter.Stream) ([]byte, error) {
	buf := make([]byte, 4096)

	if _, err := stream.Read(buf); err != nil {
		log.Printf("Failed to read from stream: %v", err)
		return nil, err
	}

	fmt.Printf("Received DATA: %s\n", string(buf))

	return buf, nil
}

func (qc *quicConnection) OnWriteStream(stream adapter.Stream, payload []byte) error {
	if _, err := stream.Write([]byte(payload)); err != nil {
		log.Printf("Failed to write to stream: %v", err)
		return err
	}

	fmt.Printf("Server sent: '%s'\n", payload)
	return nil
}

func (qc *quicConnection) OnNewStream(stream adapter.Stream) {
	defer stream.Close()
	receivedPayload, err := qc.OnReadStream(stream)
	if err != nil {
		return
	}

	if err := qc.OnWriteStream(stream, receivedPayload); err != nil {
		return
	}
}

func (qc *quicConnection) ConnectionID() string {
	return qc.connectionID
}

func (qc *quicConnection) AcceptStream(ctx context.Context) (adapter.Stream, error) {
	stream, err := qc.conn.AcceptStream(ctx)
	if err != nil {
		log.Printf("Failed to accept stream: %v", err)
		return nil, err
	}

	return NewStream(stream), nil
}

func (qc *quicConnection) CloseWithError(applicationErrorCode uint64, errorMessage string) error {
	return qc.CloseWithError(applicationErrorCode, errorMessage)
}

type quicStream struct {
	stream quic.Stream
}

func NewStream(stream quic.Stream) adapter.Stream {
	return &quicStream{
		stream: stream,
	}
}

func (qs *quicStream) Read(buf []byte) (n int, err error) {
	return qs.stream.Read(buf)
}

func (qs *quicStream) Write(p []byte) (n int, err error) {
	return qs.stream.Write(p)
}

func (qs *quicStream) Close() error {
	return qs.stream.Close()
}
