package responseWriter

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	http3streams "github.com/PogCorp/HTTP3/pkg/http3Streams"
)

type responseWriter struct {
	stream            http3streams.Http3Stream // now using an http3 stream to send the frames
	headers           http.Header
	statusCode        int
	writeHeaderCalled bool
	headerWritten     bool
	contentLength     uint64
	bytesWriten       int64
	logger            *slog.Logger
}

var _ http.ResponseWriter = &responseWriter{}

func NewResponseWriter(stream http3streams.Http3Stream, logger *slog.Logger) *responseWriter {
	return &responseWriter{
		stream:  stream,
		headers: http.Header{}, //initially empty. Headers are added during processing (response generation)
		logger:  logger,
	}
}

// returns the header map that will be sent by WriteHeader
func (w *responseWriter) Header() http.Header {
	return w.headers
}

func (w *responseWriter) HeadersWritten() bool {
	return w.headerWritten
}

func (w *responseWriter) LengthWritten() int64 {
	return w.bytesWriten
}

// copied from quic-go/http3/response_writter
func (w *responseWriter) detectContent(b []byte) {
	_, hasContentLength := w.headers["Content-Length"]
	hasContentEncoding := w.headers.Get("Content-Encoding") != ""
	if !hasContentEncoding && !hasContentLength && len(b) > 0 {
		w.headers.Set("Content-Type", http.DetectContentType(b))
	}
}

// this method configures the status code and creates the header frame that will be sent over the stream
func (w *responseWriter) WriteHeader(statusCode int) {

	if w.headerWritten {
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
		err := w.stream.SendHeader(statusCode, w.headers)
		if err != nil {
			if w.logger != nil {
				w.logger.Debug("failed to send headers", "error", err)
			}
		}
		return
	}

	// adding a date header if not present
	if _, ok := w.headers["Date"]; !ok {
		w.headers.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	}

	w.writeHeaderCalled = true // if status code >= 200, we are done writing headers
	if contentLength := w.headers.Get("Content-Length"); contentLength != "" {
		length, err := strconv.ParseUint(contentLength, 10, 63)
		if err != nil {
			if w.logger != nil {
				w.logger.Error(
					"Content-Length does not have correct format",
					"Content-Length", contentLength,
					"error", err,
				)
			}
			w.headers.Del("Content-Length")
			return
		}
		w.contentLength = length
	}
}

// writes the data to the connection
// this data []byte contains the message body that will be encapsulated in data frames
func (w *responseWriter) Write(data []byte) (int, error) {
	// check if for the given status, a body is permitted

	// if all headers are not written, call WriteHeader with status 200 by default
	if !w.writeHeaderCalled {
		w.WriteHeader(http.StatusOK) // default defined in net/http#ResponseWriter
	}

	// checking if the method allows a body
	// if the method is HEAD (returns just the headers), there shall be no body
	// interim responses (1xx), and 304 also dont allow a body
	if w.statusCode == http.StatusNoContent || (w.statusCode >= 100 && w.statusCode < 200) ||
		w.statusCode == http.StatusNotModified {
		return 0, http.ErrBodyNotAllowed
	}

	//sending the headers trough the http3 stream
	if !w.headerWritten {
		w.detectContent(data)
		if err := w.stream.SendHeader(w.statusCode, w.headers); err != nil {
			return 0, fmt.Errorf("Failed to send headers: %w", err)
		}
	}
	w.headerWritten = true

	w.bytesWriten += int64(len(data))

	// TODO: there might be a bug in the conversion bellow, since contentLength can be big enough to be negative
	if w.contentLength > 0 && w.bytesWriten > int64(w.contentLength) {
		return 0, http.ErrContentLength
	}

	n, err := w.stream.SendBody(data)
	if err != nil {
		return 0, fmt.Errorf("Failed to send data chunk: %w", err)
	}

	return n, nil
}
