package headers

import (
	"errors"
	"fmt"
	"golang.org/x/net/http/httpguts"
	"net/http"
	qpack "poghttp3/pkg/qpack"
	"strconv"
	"strings"
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

func validField(fieldName string) bool {
	return strings.ToLower(fieldName) == fieldName
}

func IsPseudo(headerField qpack.HeaderField) bool {
	return len(headerField.Name) != 0 && headerField.Name[0] == ':'
}

func (hdr *Header) IsResponseHeader() bool {
	return hdr.Status != ""
}

var pseudoHeaderHandlers = map[string]func(*Header, qpack.HeaderField){
	":path":      func(hdr *Header, headerField qpack.HeaderField) { hdr.Path = headerField.Value },
	":method":    func(hdr *Header, headerField qpack.HeaderField) { hdr.Method = headerField.Value },
	":authority": func(hdr *Header, headerField qpack.HeaderField) { hdr.Authority = headerField.Value },
	":protocol":  func(hdr *Header, headerField qpack.HeaderField) { hdr.Protocol = headerField.Value },
	":scheme":    func(hdr *Header, headerField qpack.HeaderField) { hdr.Scheme = headerField.Value },
	":status":    func(hdr *Header, headerField qpack.HeaderField) { hdr.Status = headerField.Value },
}

func validPseudoHeader(h *Header, isRequest bool) (bool, string) {
	isResponsePseudoHeader := (h.Status != "")

	if isRequest && isResponsePseudoHeader {
		return false, "invalid request pseudo header: %s"
	}
	if !isRequest && !isResponsePseudoHeader {
		return false, "invalid response pseudo header: %s"
	}

	return true, ""
}

func NewHeaderFromHeaderFields(headerFields []qpack.HeaderField, isRequest bool) (*Header, error) {
	header := &Header{
		Header: make(http.Header, len(headerFields)),
	}

	var readContentLength bool
	var contentLengthStr = ""

	for _, hf := range headerFields {
		if IsPseudo(hf) {
			if !validField(hf.Name) {
				return nil, errors.New(fmt.Sprintf("Invalid header field name: %s\n", hf.Name))
			}

			if handlePseudoHeader, ok := pseudoHeaderHandlers[hf.Name]; ok {
				handlePseudoHeader(header, hf)
			} else {
				return nil, errors.New(fmt.Sprintf("Unknown pseudo header: %s\n", hf.Name))
			}

			valid, errorMessage := validPseudoHeader(header, isRequest)
			if !valid {
				return nil, errors.New(fmt.Sprintf(errorMessage, hf.Name))
			}
		} else {
			if hf.Name == "content-length" {
				if !readContentLength {
					readContentLength = true
					contentLengthStr = hf.Value
				}
			} else {
				header.Header.Add(hf.Name, hf.Value)
			}

		}

		if !httpguts.ValidHeaderFieldValue(hf.Value) {
			return nil, errors.New(fmt.Sprintf("Invalid header field value for %s: %q", hf.Name, hf.Value))
		}
	}

	if len(contentLengthStr) > 0 {
		cl, err := strconv.ParseUint(contentLengthStr, 10, 63)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("invalid content length: %+v", err))
		}
		header.Header.Set("Content-Length", contentLengthStr)
		header.ContentLength = int64(cl)
	}

	return header, nil
}
