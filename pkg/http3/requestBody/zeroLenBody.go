package requestbody

import (
	"fmt"
	"io"

	http3errors "github.com/PogCorp/HTTP3/pkg/http3/errors"
	http3streams "github.com/PogCorp/HTTP3/pkg/http3Streams"
)

type NoContentBody struct {
	Stream http3streams.Http3Stream
}

var _ io.ReadCloser = &NoContentBody{}

func (n *NoContentBody) Read(b []byte) (int, error) {
	return 0, fmt.Errorf("trying to read from Request with no Content-Length")
}

func (n *NoContentBody) Close() error {
	n.Stream.CloseRead(http3errors.RequestCancelled)
	return nil
}
