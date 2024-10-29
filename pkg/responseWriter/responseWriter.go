package responseWriter

import (
	"bytes"
	"fmt"
	"net/http"
	//frame "poghttp3/pkg/frameParser"
	"poghttp3/pkg/http3Streams"
	//"poghttp3/pkg/qpack"
	//adapter "poghttp3/pkg/quic"
	"time"

)

type responseWriter struct{
	stream http3streams.Http3Stream // now using an http3 stream to send the frames
	headers http.Header 
	trailers http.Header
	statusCode int
	writen bool
	contentLength int64
	bytesWriten int64
	buffer bytes.Buffer
}


func NewResponseWriter(stream http3streams.Http3Stream) * responseWriter{
	return &responseWriter{
		stream: stream,
		headers: http.Header{}, //initially empty. Headers are added during processing (response generation)
	}
}


// implementing the http.ResponseWriter interface (Header(), Write([]byte), WriteHeader(int)

// returns the header map that will be sent by WriteHeader
func (w *responseWriter) Header() http.Header{
	return w.headers
}

// this method configures the status code and creates the header frame that will be sent over the stream
func (w *responseWriter) WriteHeader(statusCode int){

	if w.writen{
		// all headers and status already written. No further action needed.
		return
	}

	// validating if the status code lies in a valid interval
	if statusCode < 100 || statusCode > 999{
		panic(fmt.Sprintf("invalid status code %v in ResponseWriter.WriteHeader", statusCode))
	}
	
	w.statusCode = statusCode // writing the status code

	// if te status code is 1xx, this is an interim response (HTTP, section 15.2)
	// so we write them directly
	if statusCode < 200{
		w.WriteHeader(statusCode) //CHECK THIS THING
		return
	}

	w.writen = true // if status code >= 200, we are done writing headers
	
	// adding a date header if not present
	if _, ok := w.headers["Date"]; !ok{
		w.headers.Set("Date", time.Now().UTC().Format(http.TimeFormat));
	}

	// we defer the creating of the header frame to the Write method

}


// writes the data to the connection
// this data []byte contains the message body that will be encapsulated in data frames
func (w *responseWriter) Write(data []byte) (int, error){
	// check if for the given status, a body is permitted

	// if all headers are not written, call WriteHeader with status 200 by default
	if !w.writen{
		w.WriteHeader(http.StatusOK)// default 
	}
	
	// checking if the method allows a body
	// if the method is HEAD (returns just the headers), there shall be no body
	// interim responses (1xx), and 304 also dont allow a body
	if w.statusCode == http.StatusNoContent || (w.statusCode >= 100 && w.statusCode < 200) || 
	w.statusCode == http.StatusNotModified{
		return 0, http.ErrBodyNotAllowed
	}

	//sending the headers trough the http3 stream
	if _, err := w.stream.SendHeaders(w.headers); err != nil{
		return 0, fmt.Errorf("Failed to send headers: %w", err)
	}

		
	
	w.bytesWriten += int64(len(data))
	if(w.contentLength != 0 && w.bytesWriten > w.contentLength){
		return 0, http.ErrContentLength
	}
	

	// only send the data when the buffer hits a certain size, to enhance performance
	// this 4096 size is placeholder for now
	const maxDataFrameSize = 1
	w.buffer.Write(data)
	
	// divide it in chunks and send
	for w.buffer.Len() >= maxDataFrameSize{
		chunk := w.buffer.Next(maxDataFrameSize) // gets the slice defined by maxFrameSize
		if _, err := w.stream.SendBody(chunk); err != nil{
			return 0, fmt.Errorf("Failed to send data chunk: %w", err)
		}
	}
	// TODO: Implement a flush method to just send data, regardless of the buffer size
	
	return len(data), nil

}
