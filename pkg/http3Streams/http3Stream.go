package http3streams

import (
	"bytes"
	//"errors"
	"fmt"
	//"io"
	"net/http"
	frame "poghttp3/pkg/frameParser"
	qpackApi "poghttp3/pkg/qpack"
	qpack "poghttp3/pkg/qpack/quicgo"
	adapter "poghttp3/pkg/quic"
)

type Http3Stream interface{
	SendHeaders(headers http.Header) (int, error) //send a generic frame type
	SendBody(data []byte) (int, error)
	// trailers are the same as headers, but sent after the body.
	// we can reuse the SendHeaders function for them
//	Close() error

}

type streamState string



type RequestStream struct{
	QuicStream adapter.QuicBiStream //RequestStream uses bidirectional stream
}


// THE RESPONSE WRITER CREATES THE FRAMES (HIGH LEVEL). THE HTTPSTREAMS ENCODE THEM.

// send headers as an http3 HEADER frame, using qpack encoding
func (s *RequestStream) SendHeaders(headers http.Header) (int, error){

	var buffer bytes.Buffer
	encoder := qpack.NewQuicGoQpackEncoder()
	headerFields := make([]qpackApi.HeaderField, 0, len(headers))

	//converting the headers to qpack header field, so we can use the encoding
	// headers are key value pairs, and a key like cookie can have multiple values
	//hence we iterate through them all
	for name, values := range headers{
		for _, value := range values{
			headerFields = append(headerFields, qpackApi.HeaderField{Name: name, Value: value})
		}
	}

	// coding using qpack
	if err := encoder.Encode(&buffer, headerFields...); err != nil{
		return 0, fmt.Errorf("Error during qpack encoding: %w", err)
	}

	// creating the header frame with the coded headers
	headersFrame := &frame.HeadersFrame{
		Length: uint64(buffer.Len()),
		Headers: buffer.Bytes(),
	}

	// applying varint
	encodedFrame, err := headersFrame.Encode()
	if err != nil{
		return 0, fmt.Errorf("Error during varint encoding of the HEADERS frame: %w", err)
	}

	//sending the header frame through the quicStream
	bytesSent,err := s.QuicStream.Write(encodedFrame)

	return bytesSent, err

}

func (s *RequestStream) SendBody(data []byte) (int, error){
	// creating the DATA frame with the provided content
	dataFrame := &frame.DataFrame{
		Length: uint64(len(data)),
		Data: data,
	}

	//encoding the frame
	encodedFrame, err := dataFrame.Encode()
	if err != nil{
		return 0,fmt.Errorf("Failed during varint encoding of te DATA frame: %w", err)
	}
	
	//sending the frame
	bytesSent, err := s.QuicStream.Write(encodedFrame)

	return bytesSent, err
}












