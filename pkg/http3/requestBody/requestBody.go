package requestbody

import (
	"fmt"
	"io"
	"poghttp3/pkg/http3"
	adapter "poghttp3/pkg/quic"
	"sync"
)

type requestBody struct {
	biStream adapter.QuicBiStream
	stream   io.Reader
	// invariant, contentLength must be positive
	contentLength    int
	bytesToBeRead    int
	violationHandler func()
}

var _ RequestBody = (*requestBody)(nil)

func NewRequestBody(
	biStream adapter.QuicBiStream,
	stream io.Reader,
	contentLength int,
) (RequestBody, error) {
	if contentLength <= 0 {
		return nil, fmt.Errorf("received non-positive contentLength in Request Body Constructor")
	}

	return &requestBody{
		biStream:      biStream,
		stream:        stream,
		contentLength: contentLength,
		bytesToBeRead: contentLength,
		violationHandler: sync.OnceFunc(func() {
			biStream.Close(http3.MessageError)
		}),
	}, nil
}

func (rb *requestBody) Close() error {
	rb.biStream.CloseRead(http3.RequestCancelled)
	return nil
}

func (rb *requestBody) Read(b []byte) (n int, err error) {

	if rb.violatedContentLength() {
		rb.violationHandler()
		return 0, fmt.Errorf("Content Length Violated in Request Body")
	}

	bufSize := len(b)
	if bufSize > rb.bytesToBeRead {
		bufSize = rb.bytesToBeRead
	}

	newBuff := b[:bufSize]
	n, err = rb.stream.Read(newBuff)

	rb.bytesToBeRead -= n

	if rb.violatedContentLength() {
		rb.violationHandler()
		return n, fmt.Errorf("Content Length Violated in Request Body")
	}

	return n, err
}

func (rb *requestBody) violatedContentLength() bool {
	// TODO: change the reader to an HTTP3 Stream that must have a method to tell
	//		if there is more data to be read, thus making validation of
	//		content lenght possible
	//		Also, BiStream will not be necessary in this case, since it will be
	//		wrapped under HTTP3 Stream
	if rb.bytesToBeRead < 0 {
		return true
	}
	return false
}
