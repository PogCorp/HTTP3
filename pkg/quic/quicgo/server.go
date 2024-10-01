package quicgo

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	adapter "poghttp3/pkg/quic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
)

const addr = "localhost:4242"

type quicServer struct {
	quicApi   adapter.QuicAPI
	tlsConfig *tls.Config
	sni       string
}

func NewQuicGoServer(uri, keyfile, certfile string, api adapter.QuicAPI) (adapter.QuicServer, error) {
	certficate, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return nil, err
	}

	return &quicServer{
		quicApi:   api,
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{certficate}},
		sni:       "TODO",
	}, nil
}

func (q *quicServer) Listen() error {

	config := &quic.Config{
		EnableDatagrams: true,
		Tracer: func(ctx context.Context, p logging.Perspective, cid quic.ConnectionID) *logging.ConnectionTracer {
			quicGoCid := NewQuicGoCID(cid)
			q.quicApi.OnNewConnection(quicGoCid)
			return qlog.DefaultConnectionTracer(ctx, p, cid)
		},
		MaxIdleTimeout: time.Minute * 30,
		GetConfigForClient: func(info *quic.ClientHelloInfo) (*quic.Config, error) {
			return nil, nil
		},
	}

	listener, err := quic.ListenAddr(addr, q.tlsConfig, config)
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

func (q *quicServer) handleConnection(ctx context.Context, conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			//log.Printf("Failed to accept stream: %v", err)
			// TODO: what to do when error
			return
		}
		quicGoStream := NewStream(stream)
		q.quicApi.OnNewStream(quicGoStream)
		go q.handleStream(ctx, stream)
	}
}

func (q *quicServer) handleStream(ctx context.Context, stream quic.Stream) {
	defer stream.Close()
	quicGoStream := NewStream(stream)
	q.quicApi.OnNewStream(quicGoStream)

	buf := make([]byte, 4096)

	if _, err := stream.Read(buf); err != nil {
		log.Printf("Failed to read from stream: %v", err)
		return
	}

	fmt.Printf("Received DATA: %s\n", string(buf))
	q.quicApi.OnReadStream(quicGoStream, buf)
	q.simpleWrite("This is a response from server", stream)
}

func (q *quicServer) simpleWrite(data string, stream quic.Stream) {
	if _, err := stream.Write([]byte(data)); err != nil {
		log.Printf("Failed to write to stream: %v", err)
		return
	}

	fmt.Printf("Server sent: '%s'\n", data)
}
