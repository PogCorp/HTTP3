package quicgo

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	adapter "poghttp3/pkg/quic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
)

type quicServer struct {
	quicApi     adapter.QuicAPI
	tlsConfig   *tls.Config
	tracerToCid map[quic.ConnectionTracingID]quic.ConnectionID
	udpAddr     net.UDPAddr
}

type QuicConfig struct {
	Host     string
	Keyfile  string
	Certfile string
	Alpn     string
	Api      adapter.QuicAPI
}

func NewQuicGoServer(host, keyfile, certfile string, api adapter.QuicAPI) (adapter.QuicServer, error) {
	certficate, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return nil, err
	}

	if host == "" {
		host = ":https"
	}

	udpAddr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		return nil, err
	}

	return &quicServer{
		quicApi:     api,
		tlsConfig:   &tls.Config{Certificates: []tls.Certificate{certficate}},
		tracerToCid: make(map[quic.ConnectionTracingID]quic.ConnectionID),
		udpAddr:     *udpAddr,
	}, nil
}

func (q *quicServer) Listen() error {

	config := &quic.Config{
		EnableDatagrams: true,
		Tracer: func(ctx context.Context, p logging.Perspective, cid quic.ConnectionID) *logging.ConnectionTracer {
			traceId := ctx.Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID)
			q.tracerToCid[traceId] = cid
			return qlog.DefaultConnectionTracer(ctx, p, cid)
		},
		MaxIdleTimeout: time.Minute * 30, // TODO: this is debug only and should be removed
	}

	udpConn, err := net.ListenUDP("udp", &q.udpAddr)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	listener, err := quic.Listen(udpConn, q.tlsConfig, config)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		ctx := context.Background()
		conn, err := listener.Accept(ctx)
		if err != nil {
			log.Printf("Failed to accept connection: %v\n", err)
			continue
		}

		go q.handleConnection(ctx, conn)
	}
}

func (q *quicServer) handleConnection(ctx context.Context, conn quic.Connection) {
	connCtx := conn.Context()
	traceId := connCtx.Value(quic.ConnectionTracingKey).(quic.ConnectionTracingID)
	cid := q.tracerToCid[traceId]
	qConn := NewQuicGoConn(cid, conn)
	q.quicApi.OnNewConnection(qConn)
	defer q.quicApi.OnCanceledConn(qConn)
	go func() {
		for connCtx.Err() == nil {
			stream, err := conn.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			go q.handleUniStream(ctx, qConn, stream)
		}
	}()

	for connCtx.Err() == nil {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			log.Printf("Failed to accept stream: %v\n", err)
			// TODO: what to do when error
			return
		}
		biStream := NewBiStream(stream)
		q.quicApi.OnNewBiStream(qConn, biStream)
		go q.handleBiStream(ctx, qConn, stream)
	}
}

func (q *quicServer) handleUniStream(ctx context.Context, conn adapter.QuicConn, stream quic.ReceiveStream) {
	id := adapter.StreamId(stream.StreamID())
	q.quicApi.OnNewUniStream(conn, id)

	fmt.Println("Received unidirectional DATA")
	q.quicApi.OnReadUniStream(conn, id, stream)
}

func (q *quicServer) handleBiStream(ctx context.Context, conn adapter.QuicConn, stream quic.Stream) {
	biStream := NewBiStream(stream)
	q.quicApi.OnNewBiStream(conn, biStream)

	fmt.Println("Received bidirectional DATA")
	q.quicApi.OnReadBiStream(conn, biStream, stream)
}
