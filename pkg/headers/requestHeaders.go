package headers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	qpack "poghttp3/pkg/qpack"
	"strings"
)

func NewRequestFromHeaders(headerFields []qpack.HeaderField) (*http.Request, error) {
	hdr, err := NewHeaderFromHeaderFields(headerFields, true)
	if err != nil {
		return nil, err
	}

	// NOTE: concatenete cookie haeders 4.1.1.1 of RFC 9114
	if len(hdr.Header["Cookie"]) > 0 {
		hdr.Header.Set("Cookie", strings.Join(hdr.Header["Cookie"], "; "))
	}

	if len(hdr.Path) == 0 || len(hdr.Authority) == 0 || len(hdr.Method) == 0 {
		return nil, errors.New(":path, :authority and :method must not be empty")
	}

	u, err := url.ParseRequestURI(hdr.Path)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Invalid parsing from request uri: %+v", err))
	}

	return &http.Request{
		Method:     hdr.Method,
		URL:        u,
		Proto:      "HTTP/3.0",
		ProtoMajor: 3,
		ProtoMinor: 0,
		Header:     hdr.Header,
		// NOTE: this part must be filled with the DATA frame
		Body:          nil,
		ContentLength: hdr.ContentLength,
		Host:          hdr.Authority,
		RequestURI:    hdr.Path,
	}, nil
}
