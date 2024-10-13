package headers

import (
	"errors"
	"fmt"
	"net/http"
	qpack "poghttp3/pkg/qpack"
	"strconv"
)

func NewHttpResponseFromHeaderFields(headerFields []qpack.HeaderField) (*http.Response, error) {
	hdr, err := NewHeaderFromHeaderFields(headerFields, false)
	if err != nil {
		return nil, err
	}

	if hdr.Status == "" {
		return nil, errors.New("Missing status field")
	}

	status, err := strconv.Atoi(hdr.Status)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Invalid status code: %+v", err))
	}

	return &http.Response{
		Proto:         "HTTP/3.0",
		ProtoMajor:    3,
		Header:        hdr.Header,
		ContentLength: hdr.ContentLength,
		StatusCode:    status,
		Status:        hdr.Status + " " + http.StatusText(status),
	}, nil
}
