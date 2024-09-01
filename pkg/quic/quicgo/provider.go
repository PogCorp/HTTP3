package quicgo

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
	"log"
	"math/big"
	"os"
	"path/filepath"
	adapter "poghttp3/pkg/quic"
	"time"
)

const addr = "localhost:4242"

type QuicGoAdapter struct {
	ConnectionIdChan chan string
	ConnectionChan   chan quic.Connection
	Connections      map[string]adapter.Connection
}

func NewQuicGoAdapter() adapter.QuicAdapter {
	return &QuicGoAdapter{
		ConnectionIdChan: make(chan string, 16),
		ConnectionChan:   make(chan quic.Connection, 16),
		Connections:      make(map[string]adapter.Connection),
	}
}

func (q *QuicGoAdapter) consumeConnectionID() {
	for value := range q.ConnectionIdChan {
		fmt.Printf("Received ConnectionID: %s\n", value)
		conn := <-q.ConnectionChan
		fmt.Printf("Received Conn\n")
		q.Connections[value] = NewConnection(conn, value)
		fmt.Println("Connection registered\n")
		q.OnNewConnection(q.Connections[value])
		// go q.handleConnection(q.Connections[value])
	}
}

func (q *QuicGoAdapter) OnCancelledConnection(conn adapter.Connection) {
	fmt.Printf("Connection with connection id: %s was cancelled\n", conn.ConnectionID())
}

func (q *QuicGoAdapter) OnNewConnection(conn adapter.Connection) {
	defer conn.CloseWithError(0, "connection closed")

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("Failed to accept stream: %v", err)
			return
		}

		fmt.Printf("Handling stream from connection id: %s\n", conn.ConnectionID())
		go conn.OnNewStream(stream)
	}
}

func (q *QuicGoAdapter) Listen() error {
	qlogFilename := fmt.Sprintf("server_%s.qlog", time.Now().Format("20060102_150405"))
	qlogFile, err := os.Create(filepath.Join(".", qlogFilename))
	if err != nil {
		return fmt.Errorf("failed to create qlog file: %v", err)
	}
	defer qlogFile.Close()

	go q.consumeConnectionID()

	config := &quic.Config{
		EnableDatagrams: true,
		Tracer: func(ctx context.Context, p logging.Perspective, ci quic.ConnectionID) *logging.ConnectionTracer {
			q.ConnectionIdChan <- ci.String()
			return qlog.NewConnectionTracer(qlogFile, p, ci)
		},
		MaxIdleTimeout: time.Minute * 30,
	}

	listener, err := quic.ListenAddr(addr, generateTLSConfig(), config)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		q.ConnectionChan <- conn

		// q.OnNewConnection(conn)
	}
}

func (q *QuicGoAdapter) handleConnection(conn adapter.Connection) {
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

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}
