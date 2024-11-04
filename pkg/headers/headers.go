package headers

import (
	"fmt"
	"net/http"
	qpack "poghttp3/pkg/qpack"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/http/httpguts"
)

type Header struct {
	// NOTE: pseudo headers RFC 9114 section 8
	Path          string
	Method        string
	Authority     string // host:port
	Scheme        string
	Status        string
	ContentLength int64
	Header        http.Header
	Protocol      string
}

// all header fields must be lowercase
func validHeaderField(fieldName string) bool {
	return strings.ToLower(fieldName) == fieldName
}

func IsPseudoHeader(headerField qpack.HeaderField) bool {
	return len(headerField.Name) != 0 && headerField.Name[0] == ':'
}

func (hdr *Header) IsResponseHeader() bool {
	return hdr.Status != ""
}

func parseHeaderFromHeaderFields(headerFields []qpack.HeaderField) (*Header, error) {
	header := &Header{
		Header: make(http.Header, len(headerFields)),
	}

	readContentLength := false
	// validates that pseudo headers come before regular headers
	pseudoHeaderEnd := false

	for _, hf := range headerFields {
		if !validHeaderField(hf.Name) {
			return nil, fmt.Errorf("Got invalid header field name: %s\n", hf.Name)
		}

		if !httpguts.ValidHeaderFieldValue(hf.Value) {
			return nil, fmt.Errorf("Got invalid header field value for %s: %s", hf.Name, hf.Value)
		}

		if IsPseudoHeader(hf) {
			if pseudoHeaderEnd {
				return nil, fmt.Errorf("received pseudo header %s after regular header", hf.Name)
			}

			switch hf.Name {
			case ":path":
				header.Path = hf.Value
			case ":method":
				header.Method = hf.Value
			case ":authority":
				header.Authority = hf.Value
			case ":protocol":
				header.Protocol = hf.Value
			case ":scheme":
				header.Scheme = hf.Value
			case ":status":
				return nil, fmt.Errorf("received :status pseudo header")
			default:
				return nil, fmt.Errorf("undefined pseudo header: %s", hf.Name)
			}

		} else {
			pseudoHeaderEnd = true
			if !httpguts.ValidHeaderFieldName(hf.Name) {
				return nil, fmt.Errorf("Got header field name for %s: %s", hf.Name, hf.Value)
			}

			if hf.Name == "content-length" {
				// add Content Length value only once
				err := sync.OnceValue(func() error {
					cl, err := strconv.ParseUint(hf.Value, 10, 63)
					if err != nil {
						return fmt.Errorf("failed to parse Content-Length value, err: %s", err)
					}
					header.Header.Set("Content-Length", hf.Value)
					header.ContentLength = int64(cl)
					readContentLength = true
					return nil
				})()
				if err != nil {
					return nil, err
				}
				// check for inconsistency with duplicate Content-Length's since it MAY be
				// accepted (see section 8.6 RFC 9110)
				if readContentLength && hf.Value != header.Header.Get("Content-Length") {
					return nil, fmt.Errorf("two different instances of Content-Length received")
				}
			} else {
				header.Header.Add(hf.Name, hf.Value)
			}
		}
	}

	return header, nil
}
