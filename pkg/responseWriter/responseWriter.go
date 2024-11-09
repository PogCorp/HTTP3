package responseWriter

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	http3streams "poghttp3/pkg/http3Streams"
	"time"
)

type responseWriter struct {
	stream        http3streams.Http3Stream // now using an http3 stream to send the frames
	headers       http.Header
	trailers      http.Header // FIX: headers contain the trailers, such a element has no effect on the protocol
	statusCode    int
	writen        bool
	contentLength int64
	bytesWriten   int64
	Buffer        bytes.Buffer
	logger        *slog.Logger
}

var _ http.ResponseWriter = &responseWriter{}

func NewResponseWriter(stream http3streams.Http3Stream, logger *slog.Logger) *responseWriter {
	return &responseWriter{
		stream:  stream,
		headers: http.Header{}, //initially empty. Headers are added during processing (response generation)
		logger:  logger,
	}
}

// implementing the http.ResponseWriter interface (Header(), Write([]byte), WriteHeader(int)

// returns the header map that will be sent by WriteHeader
func (w *responseWriter) Header() http.Header {
	return w.headers
}

// this method configures the status code and creates the header frame that will be sent over the stream
func (w *responseWriter) WriteHeader(statusCode int) {

	if w.writen {
		// all headers and status already written. No further action needed.
		return
	}

	// validating if the status code lies in a valid interval
	if statusCode < 100 || statusCode > 999 {
		panic(fmt.Sprintf("invalid status code %d in ResponseWriter.WriteHeader", statusCode))
	}

	w.statusCode = statusCode // writing the status code

	// if te status code is 1xx, this is an interim response (HTTP, section 15.2)
	// so we write them directly
	if statusCode < 200 {
		_, err := w.stream.SendHeader(statusCode, w.headers)
		if err != nil {
			if w.logger != nil {
				w.logger.Debug("failed to send headers", "error", err)
			}
		}
		return
	}

	w.writen = true // if status code >= 200, we are done writing headers

	// adding a date header if not present
	if _, ok := w.headers["Date"]; !ok {
		w.headers.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	}

	//TODO: missing Content-Length attribution

	// we defer the creating of the header frame to the Write method

}

// writes the data to the connection
// this data []byte contains the message body that will be encapsulated in data frames
func (w *responseWriter) Write(data []byte) (int, error) {
	// check if for the given status, a body is permitted

	// if all headers are not written, call WriteHeader with status 200 by default
	if !w.writen {
		w.WriteHeader(http.StatusOK) // default
	}

	// checking if the method allows a body
	// if the method is HEAD (returns just the headers), there shall be no body
	// interim responses (1xx), and 304 also dont allow a body
	if w.statusCode == http.StatusNoContent || (w.statusCode >= 100 && w.statusCode < 200) ||
		w.statusCode == http.StatusNotModified {
		return 0, http.ErrBodyNotAllowed
	}

	//sending the headers trough the http3 stream
	if _, err := w.stream.SendHeader(w.statusCode, w.headers); err != nil {
		return 0, fmt.Errorf("Failed to send headers: %w", err)
	}

	w.bytesWriten += int64(len(data))
	if w.contentLength != 0 && w.bytesWriten > w.contentLength {
		return 0, http.ErrContentLength
	}

	w.Buffer.Write(data)

	if _, err := w.stream.SendBody(w.Buffer.Bytes()); err != nil {
		return 0, fmt.Errorf("Failed to send data chunk: %w", err)
	}

	// Headers sent, body sent. Now, if there are trailers, we send them in the end
	if len(w.trailers) > 0 {
		if _, err := w.stream.SendHeader(w.statusCode, w.trailers); err != nil {
			return 0, fmt.Errorf("Failed to send trailers: %w", err)
		}
	}

	return len(data), nil
}
