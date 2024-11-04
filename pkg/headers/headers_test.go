package headers

import (
	"net/http"
	"net/url"
	"poghttp3/pkg/qpack"
	"reflect"
	"testing"
)

func TestRequestParser(t *testing.T) {
	tests := []struct {
		input  []qpack.HeaderField
		expect http.Request
	}{
		{
			input: []qpack.HeaderField{
				{Name: ":path", Value: "/api"},
				{Name: ":authority", Value: "example.com"},
				{Name: ":method", Value: "POST"},
				{Name: "content-length", Value: "420"},
			},
			expect: http.Request{
				Method: "POST",
				Host:   "example.com",
				URL: &url.URL{
					Path: "/api",
				},
				Proto:         "HTTP/3.0",
				ProtoMajor:    3,
				ProtoMinor:    0,
				ContentLength: 420,
				Header: http.Header{
					"Content-Length": {"420"},
				},
				RequestURI: "/api",
			},
		},
		{
			input: []qpack.HeaderField{
				{Name: ":path", Value: "/duplicate/content/length"},
				{Name: ":authority", Value: "example.com"},
				{Name: ":method", Value: "GET"},
				{Name: "content-length", Value: "69"},
				{Name: "content-length", Value: "69"},
			},
			expect: http.Request{
				Method: "GET",
				Host:   "example.com",
				URL: &url.URL{
					Path: "/duplicate/content/length",
				},
				Proto:         "HTTP/3.0",
				ProtoMajor:    3,
				ProtoMinor:    0,
				ContentLength: 69,
				Header: http.Header{
					"Content-Length": {"69"},
				},
				RequestURI: "/duplicate/content/length",
			},
		},
	}

	for _, test := range tests {
		request, err := NewRequestFromHeaders(test.input)
		if err != nil {
			t.Fatalf("failed to parse Request from qpcack headers, err: %s", err)
		}
		if !reflect.DeepEqual(*request, test.expect) {
			t.Logf("expected: %+v", test.expect)
			t.Logf("got: %+v", request)
			t.Fatal("parsed request is different from expected one")
		}
	}

}
