package requestbody

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	http3streams "github.com/PogCorp/HTTP3/pkg/http3Streams"
	adapter "github.com/PogCorp/HTTP3/pkg/quic"
)

type mockStream struct {
	*bytes.Reader
	closeCalled bool
}

var _ http3streams.Http3Stream = &mockStream{}

func (m *mockStream) Close(reason adapter.ApplicationError) {
	m.closeCalled = true
}

func (m *mockStream) CloseRead(reason adapter.ApplicationError) {
}

func (m *mockStream) HasRemainingData() bool {
	return m.Reader.Len() > 0
}

func (m *mockStream) SendTrailers() error {
	return nil
}

func (m *mockStream) SendBody(b []byte) (int, error) {
	return 0, nil
}

func (m *mockStream) SendHeader(status int, headers http.Header) error {
	return nil
}

func TestRequestBodyReadAllContentLength(t *testing.T) {
	tests := []struct {
		data   []byte
		length int
		expect string
	}{
		{
			data: []byte{0x54, 0x68, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20,
				0x69, 0x73, 0x3a, 0x20, 0x53, 0x75, 0x6e, 0x2c, 0x20,
				0x32, 0x35, 0x20, 0x41, 0x75, 0x67, 0x20, 0x32, 0x30,
				0x32, 0x34, 0x20, 0x31, 0x36, 0x3a, 0x30, 0x35, 0x3a,
				0x33, 0x33, 0x20, 0x55, 0x54, 0x43,
			},
			length: 42,
			expect: "The time is: Sun, 25 Aug 2024 16:05:33 UTC",
		},
	}

	for _, test := range tests {
		reader := bytes.NewReader(test.data)
		body, err := NewRequestBody(&mockStream{Reader: reader}, int64(test.length))
		if err != nil {
			t.Fatal("Violated request body invariants")
		}

		result := make([]byte, test.length)
		n, err := body.Read(result)
		if err != nil {
			t.Fatalf("Error reading the entire content from body: %+v\n", err)
		}

		if n != int(test.length) {
			t.Fatalf("bytes read are no the same as content length")
		}

		t.Logf("captured data: %s", result)

		if !bytes.Equal(result, []byte(test.expect)) {
			t.Fatalf("Body from the result %s and the correct %s are not the same\n", result, test.expect)
		}
	}
}

func TestRequestBodyReadPartition(t *testing.T) {
	tests := []struct {
		data       []byte
		length     int
		partitions [][]byte
	}{
		{
			data: []byte{0x54, 0x68, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20,
				0x69, 0x73, 0x3a, 0x20, 0x53, 0x75, 0x6e, 0x2c, 0x20,
				0x32, 0x35, 0x20, 0x41, 0x75, 0x67, 0x20, 0x32, 0x30,
				0x32, 0x34, 0x20, 0x31, 0x36, 0x3a, 0x30, 0x35, 0x3a,
				0x33, 0x33, 0x20, 0x55, 0x54, 0x43,
			},
			length: 42,
			partitions: [][]byte{
				[]byte("The time is: "),
				[]byte("Sun, 25 Aug 2024 16:05:33 UTC"),
			},
		},
	}

	for _, test := range tests {

		reader := bytes.NewReader(test.data)

		body, err := NewRequestBody(&mockStream{Reader: reader}, int64(test.length))
		if err != nil {
			t.Fatal("Violated request body invariants")
		}

		for i := 0; i < len(test.partitions); i++ {
			partitionLength := len([]byte(test.partitions[i]))
			result := make([]byte, partitionLength)
			n, err := body.Read(result)
			if err != nil {
				t.Fatalf("Error reading the entire content from body: %+v\n", err)
			}

			if n != partitionLength {
				t.Fatalf("bytes read are no the same as content length")
			}

			if !bytes.Equal(result, test.partitions[i]) {
				t.Fatalf("Body from the result '%s' and the correct '%s' are not the same\n", result, test.partitions[i])
			}
		}
	}
}

func TestLengthViolations(t *testing.T) {
	buffer := bytes.NewReader([]byte("test string"))
	mockStream := &mockStream{Reader: buffer}
	body, err := NewRequestBody(mockStream, 9)
	if err != nil {
		t.Fatalf("failed to instantiate new Request Body class")
	}
	data, err := io.ReadAll(body)
	if err == nil {
		t.Fatalf("expected to received error")
	}
	if !mockStream.closeCalled {
		t.Fatalf("stream did not close after violation")
	}
	if !bytes.Equal(data, []byte("test stri")) {
		t.Fatalf("expected 'test stri', got %s", data)
	}
}
