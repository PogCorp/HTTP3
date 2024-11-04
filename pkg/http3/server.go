package http3

import (
	"io"
	"log/slog"
	"net/http"
	frames "poghttp3/pkg/frameParser"
	"poghttp3/pkg/headers"
	http3errors "poghttp3/pkg/http3/errors"
	requestbody "poghttp3/pkg/http3/requestBody"
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
			conn.Close(http3errors.StreamCreationError)
			return
		}
		s.handleControlStream(conn, id, reader)
	case QPackEncoder:
		if swapped := serverConn.receivedQPackEncoder.CompareAndSwap(false, true); !swapped {
			conn.Close(http3errors.StreamCreationError)
			return
		}
		// TODO: dynamic table management should be arround here
		return
	case PushStream: // client send a push stream, which is not permited, only the server can
		conn.Close(http3errors.StreamCreationError)
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
		stream.Close(http3errors.FrameError)
		return
	}
	headerFrame, ok := frame.(*frames.HeadersFrame)
	if !ok {
		if s.logger != nil {
			s.logger.Debug("in bidirectional stream failed to read frame", "stream ID", stream.ID())
		}
		stream.Close(http3errors.FrameError)
		return
	}

	hdr, err := s.decoder.Decode(headerFrame.Headers)
	if err != nil {
		if s.logger != nil {
			s.logger.Debug("in bidirectional failed to decode header frame", "stream ID", stream.ID(), "error", err)
		}
		conn.Close(http3errors.GeneralProtocolError)
		return
	}

	request, err := headers.NewRequestFromHeaders(hdr)
	if err != nil {
		if s.logger != nil {
			s.logger.Debug("failed to parse request", "stream ID", stream.ID(), "error", err)
		}
		stream.Close(http3errors.MessageError)
		return
	}

	request.RemoteAddr = conn.RemoteAddress()
	contentLength := int64(0)
	if _, ok := request.Header["Content-Length"]; ok && request.ContentLength >= 0 {
		contentLength = request.ContentLength
	}

	// TODO: configure http3 stream

	var body io.ReadCloser
	switch true {
	case contentLength == 0:
		// TODO: add io.ReaderCloser that does nothing
	case contentLength > 0:
		body, err = requestbody.NewRequestBody(stream, reader, contentLength)
		if err != nil {
			panic("request body received non-positive value in positive switch clause")
		}
	case contentLength < 0:
		if s.logger != nil {
			s.logger.Debug("received negative content length", "stream ID", stream.ID(), "error", err)
		}
		stream.Close(http3errors.GeneralProtocolError)
		return
	}

	request.Body = body

	if s.logger != nil {
		s.logger.Debug(
			"handling request",
			"stream ID", stream.ID(),
			"method", request.Method,
			"uri", request.RequestURI,
		)
	}

	// TODO: configure response writter

	stream.CloseRead(http3errors.NoError) // similar to shutdown(fd, SHUT_RD)
	stream.WriteFin()
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
