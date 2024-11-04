package http3streams

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	frame "poghttp3/pkg/frameParser"
	qpackApi "poghttp3/pkg/qpack"
	qpack "poghttp3/pkg/qpack/quicgo"
	adapter "poghttp3/pkg/quic"
	"strings"
)

type Http3Stream interface{
	SendHeaders(headers http.Header) (int, error) //send a generic frame type
	SendBody(data []byte) (int, error)
	// trailers are the same as headers, but sent after the body.
	// we can reuse the SendHeaders function for them
	Close()
	ReadData()([]frame.Frame, error)

}


type RequestStream struct{
	QuicStream adapter.QuicBiStream //RequestStream uses bidirectional stream
	QpackEncoder qpackApi.QpackApi
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
		lowerCaseName := strings.ToLower(name) //rfc states that characters in field names must be lowercased before encoding
		for _, value := range values{
			headerFields = append(headerFields, qpackApi.HeaderField{Name: lowerCaseName, Value: value})
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

func (s *RequestStream) Close(reason adapter.ApplicationError){
	s.QuicStream.Close(reason)
}

// ======== Reading Data ========= //
// to read data we must implement the Read() method so that BiStream implements the io.Reader interface
// wich is the used as the frame parser parameter. Hence why we define the quicBiStreamReader structure



func (s *RequestStream) ReadData(data []byte) (int, error){
	// each cal to this function fills up the buffer for incremental processing
	// receive raw data from the quic streams
	// uses the frame parser to decode each frame.
	// error validation
	reader := bytes.NewReader(data)
	parser := frame.NewFrameParser(reader)
	trailerRcv := false
	var bytesInFrame uint64
	
	// loop to process the next frame
	// only if the current frame is empty. 
	if bytesInFrame == 0{
	parser:	
		for{
			parsedFrame, err := parser.ParseNextFrame()
			if err != nil{
				// if it is an EOF error, the stream has been fully ReadData
				if errors.Is(err, io.EOF){
					return 0, io.EOF
				}
					return 0,fmt.Errorf("Failed to parse frame: %w", err)
			}

			// processing each frames
			switch frame := parsedFrame.(type) {
			case *frame.DataFrame:
				// if a data frames is received after a trailer, this is an error condition
				if trailerRcv{
					return 0, errors.New("DATA frame received after trailers")
				}
				bytesInFrame = frame.Length
				break parser
			
			case *frame.HeadersFrame:
				if trailerRcv{
					return 0, errors.New("HEADER frame received after trailers")
				}
				trailerRcv = true // after the header was received, only trailers will be allowed (after data)
				
			default:
				s.QuicStream.Close(0x0)
				return 0, fmt.Errorf("Unexpected frame type: %T", frame)
				}
			}
		}
	

	// parcial reading of the current frame ReadData
	var n int
	var err error = nil
	var bytesRead int

	if bytesInFrame < uint64(len(data)){
		//ajusting the buffer to read only the necessary
		n, err = reader.Read(data[:bytesInFrame]) // reads what is left
	}else{
		// if the frame is full, read it all
		n, err = reader.Read(data)
	}

	bytesInFrame -= uint64(n)
	bytesRead += n

	return bytesRead, err
}














