package requestbody

import (
	"io"
	"poghttp3/pkg/http3"
	adapter "poghttp3/pkg/quic"
)

type requestBody struct {
	biStream      adapter.QuicBiStream
	stream        io.Reader
	contentLength int
	bytesToBeRead int
}

var _ RequestBody = (*requestBody)(nil)

func NewRequestBody(biStream adapter.QuicBiStream, stream io.Reader, contentLength int) RequestBody {
	return &requestBody{
		biStream:      biStream,
		stream:        stream,
		contentLength: contentLength,
		bytesToBeRead: contentLength,
	}
}

func (rb *requestBody) Close() error {
	rb.biStream.CloseRead(http3.RequestCancelled)
	return nil
}

func (rb *requestBody) Read(dest []byte) (n int, err error) {
	bufSize := len(dest)
	if bufSize > rb.bytesToBeRead {
		bufSize = rb.bytesToBeRead
	}

	newBuff := dest[:bufSize]
	n, err = rb.stream.Read(newBuff)

	rb.bytesToBeRead -= n

	return n, err
}
