package http3

import (
	"io"
	"log/slog"
	"net/http"
	frames "poghttp3/pkg/frameParser"
	qpack "poghttp3/pkg/qpack"
	adapter "poghttp3/pkg/quic"
)

const (
	ControlStream adapter.StreamType = 0x00
	PushStream    adapter.StreamType = 0x01
	QPackEncoder  adapter.StreamType = 0x02
	QPackDecoder  adapter.StreamType = 0x03
)

const ALPNH3Protocol = "h3"

type Settings struct {
	Datagrams           bool
	ExtendedConnect     bool
	MaxFieldSectionSize uint64
}

type Server struct {
	Addr    string
	Handler http.Handler
	decoder qpack.QpackApi

	logger      *slog.Logger
	connections map[adapter.QuicConn]*connection
}

func NewServer(addr string, decoder qpack.QpackApi, handler http.Handler) *Server {
	return &Server{
		Addr:        addr,
		Handler:     handler,
		decoder:     decoder,
		logger:      slog.Default(),
		connections: make(map[adapter.QuicConn]*connection),
	}
}

func (s *Server) OnNewUniStream(conn adapter.QuicConn, id adapter.StreamId) {
	if s.logger != nil {
		s.logger.Debug("received new unidirectiona stream", "stream ID", id)
	}
}

func (s *Server) OnReadUniStream(conn adapter.QuicConn, id adapter.StreamId, reader io.Reader) {
	serverConn, ok := s.connections[conn]
	if !ok {
		panic("server connection was not registred and on new unidirection stream was called out of order")
	}
	streamType, err := frames.StreamTypeExtractor(reader)
	if err != nil {
		if s.logger != nil {
			s.logger.Debug("failed to read type from stream", "conn ID", conn.String(), "error", err)
		}
		return
	}

	switch streamType {
	case ControlStream:
		if swapped := serverConn.receivedControl.CompareAndSwap(false, true); !swapped {
			conn.Close(StreamCreationError)
			return
		}
		s.handleControlStream(conn, id, reader)
	case QPackEncoder:
		if swapped := serverConn.receivedQPackEncoder.CompareAndSwap(false, true); !swapped {
			conn.Close(StreamCreationError)
			return
		}
		// TODO: dynamic table management should be arround here
		return
	case PushStream: // client send a push stream, which is not permited, only the server can
		conn.Close(StreamCreationError)
		return
	}
}

func (s *Server) OnNewBiStream(conn adapter.QuicConn, stream adapter.QuicBiStream) {
	if s.logger != nil {
		s.logger.Debug("new stream created", "conn ID", conn.String(), "stream ID", stream.ID())
	}
}

func (s *Server) OnReadBiStream(conn adapter.QuicConn, stream adapter.QuicBiStream, reader io.Reader) {
	parser := frames.NewFrameParser(reader)
	frame, err := parser.ParseNextFrame()
	if err != nil {
		if s.logger != nil {
			s.logger.Debug("in bidirectional stream failed to read frame", "stream ID", stream.ID())
		}
		stream.Close(FrameError)
		return
	}
	headerFrame, ok := frame.(*frames.HeadersFrame)
	if !ok {
		if s.logger != nil {
			s.logger.Debug("in bidirectional stream failed to read frame", "stream ID", stream.ID())
		}
		stream.Close(FrameError)
		return
	}

	// TODO: use the result with requestFromHeader to convert this into a *http.Request
	_, err = s.decoder.Decode(headerFrame.Headers)
	if err != nil {
		if s.logger != nil {
			s.logger.Debug("in bidirectional failed to decode header frame", "stream ID", stream.ID(), "error", err)
		}
		conn.Close(GeneralProtocolError)
		return
	}
}

func (s *Server) OnCanceledConn(conn adapter.QuicConn) {
	if s.logger != nil {
		s.logger.Debug("clossing connection", "conn ID", conn.String())
	}
}

func (s *Server) OnNewConnection(conn adapter.QuicConn) {
	stream, err := conn.CreateUniStream(ControlStream)
	if err != nil {
		if s.logger != nil {
			s.logger.Debug("failed to create control stream", "conn ID", conn.String(), "error", err)
		}
		return
	}

	settings := map[frames.Setting]uint64{
		frames.ExtendedConnect: 1,
	}
	frame := frames.NewSettingsFrame(settings)
	settingsBytes, err := frame.Encode()
	if err != nil {
		if s.logger != nil {
			s.logger.Debug("failed to encode settings frame", "conn ID", conn.String(), "error", err)
		}
		return
	}

	_, err = stream.Write(settingsBytes)
	if err != nil {
		if s.logger != nil {
			s.logger.Debug("failed to send settings frame", "conn ID", conn.String(), "error", err)
		}
		return
	}

	// TODO: create decoder and insert it into connection once dynamic table is supported

	s.connections[conn] = &connection{
		controlStream: stream,
	}
}
