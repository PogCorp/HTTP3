package requestbody

import (
	"fmt"
	"io"
	"sync"

	http3errors "github.com/PogCorp/HTTP3/pkg/http3/errors"
	http3streams "github.com/PogCorp/HTTP3/pkg/http3Streams"
)

type requestBody struct {
	stream http3streams.Http3Stream
	// invariant, contentLength must be positive
	contentLength    int64
	bytesToBeRead    int64
	violationHandler func()
}

var _ io.ReadCloser = &requestBody{}

func NewRequestBody(
	stream http3streams.Http3Stream,
	contentLength int64,
) (RequestBody, error) {
	if contentLength <= 0 {
		return nil, fmt.Errorf("received non-positive contentLength in Request Body Constructor")
	}

	return &requestBody{
		stream:        stream,
		contentLength: contentLength,
		bytesToBeRead: contentLength,
		violationHandler: sync.OnceFunc(func() {
			stream.Close(http3errors.MessageError)
		}),
	}, nil
}

func (rb *requestBody) Close() error {
	rb.stream.CloseRead(http3errors.RequestCancelled)
	return nil
}

func (rb *requestBody) Read(b []byte) (n int, err error) {

	if rb.violatedContentLength() {
		rb.violationHandler()
		return 0, fmt.Errorf("Content Length Violated in Request Body")
	}

	bufSize := min(int64(len(b)), rb.bytesToBeRead)

	newBuff := b[:bufSize]
	n, err = rb.stream.Read(newBuff)

	rb.bytesToBeRead -= int64(n)

	if rb.violatedContentLength() {
		rb.violationHandler()
		return n, fmt.Errorf("Content Length Violated in Request Body")
	}

	return n, err
}

func (rb *requestBody) violatedContentLength() bool {
	if rb.bytesToBeRead < 0 || rb.bytesToBeRead == 0 && rb.stream.HasRemainingData() {
		return true
	}
	return false
}
