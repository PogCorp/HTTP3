package http3streams

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	frame "poghttp3/pkg/frameParser"
	http3errors "poghttp3/pkg/http3/errors"
	qpackApi "poghttp3/pkg/qpack"
	adapter "poghttp3/pkg/quic"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"
)

type Http3Stream interface {
	io.Reader
	SendHeader(status int, headers http.Header) error //send a generic frame type
	SendBody(data []byte) (int, error)
	// trailers are the same as headers, but sent after the body.
	SendTrailers() error
	HasRemainingData() bool
	Close(reason adapter.ApplicationError)
}

type RequestStream struct {
	QuicStream    adapter.QuicBiStream //RequestStream uses bidirectional stream
	QpackEncoder  qpackApi.QpackApi
	reader        io.Reader
	remainingData uint64
	trailers      http.Header
	bodySent      bool
}

var _ Http3Stream = &RequestStream{}

func NewRequestStream(streamReader io.Reader, stream adapter.QuicBiStream, qpack qpackApi.QpackApi) Http3Stream {
	return &RequestStream{
		reader:       streamReader,
		QuicStream:   stream,
		QpackEncoder: qpack,
		trailers:     make(http.Header),
	}
}

// THE RESPONSE WRITER CREATES THE FRAMES (HIGH LEVEL). THE HTTPSTREAMS ENCODE THEM.

// send headers as an http3 HEADER frame, using qpack encoding
func (s *RequestStream) SendHeader(status int, header http.Header) error {

	headerFields := make([]qpackApi.HeaderField, 0, len(header)+1)
	headerFields = append(headerFields, qpackApi.HeaderField{Name: ":status", Value: strconv.Itoa(status)})
	trailerFilter := make(map[string]bool)

	for _, trailer := range header["Trailers"] {
		// Split is necessary here since trailers can be appended into one string separated by a comma
		for _, value := range strings.Split(trailer, ",") {
			cannonicalTrailer := textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(value))
			if httpguts.ValidTrailerHeader(cannonicalTrailer) {
				trailerFilter[cannonicalTrailer] = true
			}
		}
	}

	//converting the headers to qpack header field, so we can use the encoding
	// headers are key value pairs, and a key like cookie can have multiple values
	//hence we iterate through them all
	for name, values := range header {
		// filter trailers out
		if _, isTrailer := trailerFilter[name]; isTrailer {
			for _, value := range values {
				s.trailers.Add(name, value)
			}
			continue
		}
		if strings.HasPrefix(name, http.TrailerPrefix) {
			trimedName := strings.TrimPrefix(name, http.TrailerPrefix)
			for _, value := range values {
				s.trailers.Add(trimedName, value)
			}
			continue
		}

		lowerCaseName := strings.ToLower(name) //rfc states that characters in field names must be lowercased before encoding
		for _, value := range values {
			headerFields = append(
				headerFields,
				qpackApi.HeaderField{
					Name:  lowerCaseName,
					Value: value,
				})
		}
	}
	headersFrame, err := frame.NewHeadersFrame(s.QpackEncoder, headerFields...)
	if err != nil {
		return fmt.Errorf("Error when creating header frame: %s", err)
	}

	encodedFrame, err := headersFrame.Encode()
	if err != nil {
		return fmt.Errorf("Error during varint encoding of the HEADERS frame: %s", err)
	}

	//sending the header frame through the quicStream
	_, err = s.QuicStream.Write(encodedFrame)

	return err

}

func (s *RequestStream) SendBody(data []byte) (int, error) {
	// creating the DATA frame with the provided content
	dataFrame := &frame.DataFrame{
		Length: uint64(len(data)),
		Data:   data,
	}

	//encoding the frame
	encodedFrame, err := dataFrame.Encode()
	if err != nil {
		return 0, fmt.Errorf("Failed during varint encoding of te DATA frame: %w", err)
	}

	//sending the frame
	n, err := s.QuicStream.Write(encodedFrame)
	s.bodySent = true

	return n, err
}

func (s *RequestStream) Close(reason adapter.ApplicationError) {
	s.QuicStream.Close(reason)
}

// ======== Reading Data ========= //
// to read data we must implement the Read() method so that BiStream implements the io.Reader interface
// wich is the used as the frame parser parameter. Hence why we define the quicBiStreamReader structure

func (s *RequestStream) Read(data []byte) (int, error) {
	var n int
	var err error

	// each call to this function fills up the buffer for incremental processing
	// receive raw data from the quic streams
	// uses the frame parser to decode each frame.
	// error validation
	parser := frame.NewFrameParser(s.reader)
	trailerRcv := false
	dataFrameRcv := false

	// loop to process the next frame
	// only if the current frame is empty.
	if s.remainingData == 0 {
		for !dataFrameRcv {
			parsedFrame, err := parser.ParseNextFrame()
			if err != nil {
				// if it is an EOF error, the stream has been fully ReadData
				if errors.Is(err, io.EOF) {
					return 0, io.EOF
				}
				return 0, fmt.Errorf("Failed to parse frame: %w", err)
			}

			// processing each frames
			switch frame := parsedFrame.(type) {
			case *frame.DataFrame:
				// if a data frames is received after a trailer, this is an error condition
				if trailerRcv {
					return 0, errors.New("DATA frame received after trailers")
				}
				s.remainingData = frame.Length
				dataFrameRcv = true

			case *frame.HeadersFrame:
				if trailerRcv {
					return 0, errors.New("HEADER frame received after trailers")
				}
				trailerRcv = true // after the header was received, only trailers will be allowed (after data)

			default:
				s.QuicStream.Close(http3errors.FrameUnexpected)
				return 0, fmt.Errorf("Unexpected frame type: %s", reflect.TypeOf(frame).String())
			}
		}
	}

	peekLength := min(uint64(len(data)), s.remainingData)
	n, err = s.reader.Read(data[:peekLength])

	s.remainingData -= uint64(n)

	return n, err
}

func (s *RequestStream) SendTrailers() error {
	if !s.bodySent {
		return fmt.Errorf("cannot send trailers before sending the body")
	}
	var headerFields []qpackApi.HeaderField
	for name, values := range s.trailers {
		lowerCaseName := strings.ToLower(name)
		for _, value := range values {
			headerFields = append(
				headerFields,
				qpackApi.HeaderField{
					Name:  lowerCaseName,
					Value: value,
				},
			)
		}
	}
	headersFrame, err := frame.NewHeadersFrame(s.QpackEncoder, headerFields...)
	if err != nil {
		return fmt.Errorf("Error when creating header frame: %s", err)
	}

	encodedFrame, err := headersFrame.Encode()
	if err != nil {
		return fmt.Errorf("Error during varint encoding of the HEADERS frame: %s", err)
	}

	//sending the header frame through the quicStream
	_, err = s.QuicStream.Write(encodedFrame)

	return err
}

func (s *RequestStream) HasRemainingData() bool {
	return s.remainingData > 0
}
