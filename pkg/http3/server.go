package http3

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"strconv"

	http3errors "github.com/PogCorp/HTTP3/pkg/http3/errors"
	requestbody "github.com/PogCorp/HTTP3/pkg/http3/requestBody"
	http3streams "github.com/PogCorp/HTTP3/pkg/http3Streams"
	qpack "github.com/PogCorp/HTTP3/pkg/qpack"
	adapter "github.com/PogCorp/HTTP3/pkg/quic"
	"github.com/PogCorp/HTTP3/pkg/responseWriter"

	"github.com/PogCorp/HTTP3/pkg/headers"

	frames "github.com/PogCorp/HTTP3/pkg/frameParser"
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
	Addr           string
	Handler        http.Handler
	decoderFactory qpack.Factory

	logger      *slog.Logger
	connections map[adapter.QuicConn]*connection
}

func NewServer(addr string, decoderFactory qpack.Factory, handler http.Handler) *Server {
	return &Server{
		Addr:           addr,
		Handler:        handler,
		decoderFactory: decoderFactory,
		logger:         slog.Default(),
		connections:    make(map[adapter.QuicConn]*connection),
	}
}

func (s *Server) OnNewUniStream(conn adapter.QuicConn, id adapter.StreamId) {
	if s.logger != nil {
		s.logger.Debug("received new unidirectiona stream", "stream ID", id)
	}
}

func (s *Server) OnReadUniStream(conn adapter.QuicConn, id adapter.StreamId, reader io.Reader) {
	httpConn, ok := s.connections[conn]
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
		if swapped := httpConn.receivedControl.CompareAndSwap(false, true); !swapped {
			conn.Close(http3errors.StreamCreationError)
			return
		}
		s.handleControlStream(conn, id, reader)
	case QPackEncoder:
		if swapped := httpConn.receivedQPackEncoder.CompareAndSwap(false, true); !swapped {
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
	httpConn, ok := s.connections[conn]
	if !ok {
		panic(fmt.Sprintf("no http connection created for %s", conn.String()))
	}

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

	hdr, err := httpConn.qpackDecoder.Decode(headerFrame.Headers)
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

	httpStream := http3streams.NewRequestStream(reader, stream, httpConn.qpackDecoder)

	var body io.ReadCloser
	switch true {
	case contentLength == 0:
		body = &requestbody.NoContentBody{Stream: httpStream}
	case contentLength > 0:
		body, err = requestbody.NewRequestBody(httpStream, contentLength)
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

	handler := s.Handler
	if handler == nil {
		handler = http.DefaultServeMux
	}
	responseWritter := responseWriter.NewResponseWriter(httpStream, s.logger)

	hasPanicked := false
	func() {
		// Copied from quic-go/http/server
		defer func() {
			if p := recover(); p != nil {
				hasPanicked = true
				if p == http.ErrAbortHandler {
					return
				}

				const size = 64 << 10
				buf := make([]byte, size)
				buf = buf[:runtime.Stack(buf, false)]
				logger := s.logger
				if logger == nil {
					logger = slog.Default()
				}
				logger.Error("http: panic serving", "arg", p, "trace", string(buf))
			}
		}()
		handler.ServeHTTP(responseWritter, request)
	}()

	if hasPanicked {
		httpStream.Close(http3errors.InternalError)
		return
	} else {
		if !responseWritter.HeadersWritten() {
			header := responseWritter.Header()
			if _, hasContentLength := header["Content-Length"]; !hasContentLength {
				header.Set("Content-Length", strconv.FormatInt(responseWritter.LengthWritten(), 10))
			}
			_, err = responseWritter.Write(nil) //
			if err != nil {
				if s.logger != nil {
					s.logger.Debug("failed to send response", "stream ID", stream.ID(), "error", err)
				}
			}
		}
	}

	err = httpStream.SendTrailers()
	if err != nil {
		if s.logger != nil {
			s.logger.Debug("failed to send trailers", "stream ID", stream.ID(), "error", err)
		}
	}

	httpStream.CloseRead(http3errors.NoError) // similar to shutdown(fd, SHUT_RD)
	stream.WriteFin()                         // writes the FIN packet of QUIC, marking the end of the interaction
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

	decoder := s.decoderFactory.CreateEncoderDecoder()

	s.connections[conn] = &connection{
		controlStream: stream,
		qpackDecoder:  decoder,
	}
}
