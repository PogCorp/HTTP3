package headers

import (
	"fmt"
	"net/http"
	qpack "poghttp3/pkg/qpack"
	"strconv"
)

// NOTE: client side operation, therefore not needed for the moment
func NewHttpResponseFromHeaderFields(headerFields []qpack.HeaderField) (*http.Response, error) {
	hdr, err := parseHeaderFromHeaderFields(headerFields, false)
	if err != nil {
		return nil, err
	}

	if hdr.Status == "" {
		// see section 4.3.2 RFC 9114
		return nil, fmt.Errorf("Obligatory pseudo header :status missing in response")
	}

	status, err := strconv.Atoi(hdr.Status)
	if err != nil {
		return nil, fmt.Errorf("Invalid status code: %+v", err)
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
