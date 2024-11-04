package headers

import (
	"fmt"
	"net/http"
	"net/url"
	qpack "poghttp3/pkg/qpack"
	"strings"
)

func NewRequestFromHeaders(headerFields []qpack.HeaderField) (*http.Request, error) {
	hdr, err := parseHeaderFromHeaderFields(headerFields)
	if err != nil {
		return nil, err
	}

	// NOTE: concatenete cookie haeders 4.1.1.1 of RFC 9114
	if len(hdr.Header["Cookie"]) > 0 {
		hdr.Header.Set("Cookie", strings.Join(hdr.Header["Cookie"], "; "))
	}

	if len(hdr.Path) == 0 || len(hdr.Authority) == 0 || len(hdr.Method) == 0 {
		return nil, fmt.Errorf("the pseudo headers :path, :authority and :method are obligatory")
	}

	if hdr.Protocol != "" {
		return nil, fmt.Errorf("extended connect is not yet implemented")
	}

	u, err := url.ParseRequestURI(hdr.Path)
	if err != nil {
		return nil, fmt.Errorf("Invalid parsing from request uri: %s", err)
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
