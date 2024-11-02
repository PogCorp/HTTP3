package requestbody

import (
	"bytes"
	"io"
	frameparser "poghttp3/pkg/frameParser"
	"reflect"
	"testing"
)

var dataFrame = []byte{
	0x0, 0x2a, 0x54, 0x68, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65,
	0x20, 0x69, 0x73, 0x3a, 0x20, 0x53, 0x75, 0x6e, 0x2c, 0x20,
	0x32, 0x35, 0x20, 0x41, 0x75, 0x67, 0x20, 0x32, 0x30, 0x32,
	0x34, 0x20, 0x31, 0x36, 0x3a, 0x30, 0x35, 0x3a, 0x33, 0x33,
	0x20, 0x55, 0x54, 0x43,
}

func newMockDataFrame(reader io.Reader, t *testing.T) *frameparser.DataFrame {
	parser := frameparser.NewFrameParser(reader)
	frame, err := parser.ParseNextFrame()
	if err != nil {
		t.Fatalf("Failed to decode %s: err: %s", reflect.TypeOf(&frameparser.DataFrame{}).Name(), err)
	}

	parsedDataFrame, ok := frame.(*frameparser.DataFrame)
	if !ok {
		t.Fatalf("Frame Parser returned incorrect type")
	}

	return parsedDataFrame
}

const bodyText = "The time is: Sun, 25 Aug 2024 16:05:33 UTC"

func TestNewRequestBodyReadEntireContentLength(t *testing.T) {
	reader := bytes.NewReader(dataFrame)
	parsedDataFrame := newMockDataFrame(reader, t)

	body := NewRequestBody(nil, reader, int(parsedDataFrame.Length))

	result := make([]byte, parsedDataFrame.Length)
	n, err := body.Read(result)
	if err != nil {
		t.Fatalf("Error reading the entire content from body: %+v\n", err)
	}

	if n != int(parsedDataFrame.Length) {
		t.Fatalf("bytes read are no the same as content length")
	}

	t.Logf("CONTENT IS: %s", string(result))

	if string(result) != bodyText {
		t.Fatalf("Body from the result %s and the correct %s are not the same\n", string(result), bodyText)
	}
}

func TestNewRequestBodyReadInParts(t *testing.T) {
	reader := bytes.NewReader(dataFrame)
	parsedDataFrame := newMockDataFrame(reader, t)

	body := NewRequestBody(nil, reader, int(parsedDataFrame.Length))

	partConfig := []struct {
		result string
	}{
		{
			result: "The time is: ",
		},
		{
			result: "Sun, 25 Aug 2024 16:05:33 UTC",
		},
	}

	for i := 0; i < len(partConfig); i++ {
		partLength := len([]byte(partConfig[i].result))
		result := make([]byte, partLength)
		n, err := body.Read(result)
		if err != nil {
			t.Fatalf("Error reading the entire content from body: %+v\n", err)
		}

		if n != partLength {
			t.Fatalf("bytes read are no the same as content length")
		}

		t.Logf("PART IS: %s", string(result))

		if string(result) != partConfig[i].result {
			t.Fatalf("Body from the result %s and the correct %s are not the same\n", string(result), bodyText)
		}
	}

}
