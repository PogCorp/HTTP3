package responseWriter

import (
	"bytes"
	"fmt"
	"net/http"
	adapter "poghttp3/pkg/quic"
	"time"
)

type responseWriter struct{
	conn adapter.QuicCID // connection ID to identify the connection, and the stream inside said connection to send the data
	stream adapter.QuicStream 
	headers http.Header // string map (key -> header field, value -> actual field value (Content-Type: text/html)
	statusCode int
	writen bool // defines whether the header was already written (to satisfy headers sent before data)
	contentLength int64
	bytesWriten int64
	buffer bytes.Buffer 
}


func NewResponseWriter(stream adapter.QuicStream, conn adapter.QuicCID) * responseWriter{
	return &responseWriter{
		conn: conn,
		stream: stream,
		headers: http.Header{}, //initially empty. Headers are added during processing (response generation)
	}
}


// implementing the http.ResponseWriter interface (Header(), Write([]byte), WriteHeader(int)

// returns the header map that will be sent by WriteHeader
func (w *responseWriter) Header() http.Header{
	return w.headers
}

func (w *responseWriter) WriteHeader(statusCode int){

	if w.writen{
		// all headers already written. No further action needed.
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
		w.WriteHeader(statusCode)
		return
	}

	w.writen = true // if status code >= 200, we are done writing headers
	
	// adding a date header if not present
	if _, ok := w.headers["Date"]; !ok{
		w.headers.Set("Date", time.Now().UTC().Format(http.TimeFormat));
	}

}


// writes the data to the connection
func (w *responseWriter) Write(data []byte) (int, error){
	// check if for the given status, a body is permitted

	// if all headers are not written, call WriteHeader with status 200 by default
	if !w.writen{
		w.WriteHeader(http.StatusOK)// default in go
	}
	
	// checking if the method allows a body
	// if the method is HEAD (returns just the headers), there shall be no body
	// interim responses (1xx), and 304 also dont allow a body
	if w.statusCode == http.StatusNoContent || (w.statusCode >= 100 && w.statusCode < 200) || 
	w.statusCode == http.StatusNotModified{
		return 0, http.ErrBodyNotAllowed
	}
	
	w.bytesWriten += int64(len(data))
	if(w.contentLength != 0 && w.bytesWriten > w.contentLength){
		return 0, http.ErrContentLength
	}
	
	// adding the data to the buffer
	w.buffer.Write(data)

	// only send the data when the buffer hits a certain size, to enhance performance
	// this 4096 size is placeholder for now

	if w.buffer.Len() > 4096{
		_, err := w.stream.Write(w.buffer.Bytes())
		w.buffer.Reset() // cleaning the buffer after sending

		if err != nil{
			return 0, err
		}
	}
	
	// TODO: Implement a flush method to just send data, regardless of the buffer size

	return len(data), nil

}
