package requestbody

import "io"

type RequestBody interface {
	io.ReadCloser
}
