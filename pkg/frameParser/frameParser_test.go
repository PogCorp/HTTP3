package frameparser

import (
	"bytes"
	"io"
	adapter "poghttp3/pkg/qpack"
	qpack "poghttp3/pkg/qpack/quicgo"
	"reflect"
	"testing"
)

// TEST: integration tests that test the interaction of encoding frames and decoding from them back

func TestEncodeDecodeHeadersFrame(t *testing.T) {
	qpack := qpack.NewQuicGoQpackEncoder()
	buf := &bytes.Buffer{}
	err := qpack.Encode(buf, adapter.HeaderField{Name: "Test Name", Value: "Test Headers"})
	if err != nil {
		t.Fatalf("Failed to encode HeadersField content: %v", err)
	}

	hf := &HeadersFrame{
		Length:  uint64(buf.Len()),
		Headers: buf.Bytes(),
	}

	encoded, err := hf.Encode()
	if err != nil {
		t.Fatalf("Failed to encode HeadersFrame: %v", err)
	}

	reader := bytes.NewReader(encoded)

	parser := NewFrameParser(reader)
	frame, err := parser.ParseNextFrame()
	if err != nil {
		t.Fatalf("Failed to decode HeadersFrame: %v", err)
	}

	decodedHeadersFrame, ok := frame.(*HeadersFrame)
	if !ok {
		t.Fatalf("Frame Parser returned incorrect type")
	}

	if !bytes.Equal(hf.Headers, decodedHeadersFrame.Headers) {
		t.Errorf("Decoded data do not match: expected %v, got %v", hf.Headers, decodedHeadersFrame.Headers)
	}
}

func TestEncodeDecodeDataFrame(t *testing.T) {
	data := []byte("Hello, HTTP/3")
	df := &DataFrame{
		Length: uint64(len(data)),
		Data:   data,
	}

	encoded, err := df.Encode()
	if err != nil {
		t.Fatalf("Failed to encode DataFrame: %v", err)
	}

	reader := bytes.NewReader(encoded)

	parser := NewFrameParser(reader)
	frame, err := parser.ParseNextFrame()
	if err != nil {
		t.Fatalf("Failed to decode DataFrame: %v", err)
	}

	decodedDataFrame, ok := frame.(*DataFrame)
	if !ok {
		t.Fatalf("Frame Parser returned incorrect type")
	}

	decodedDataFrame.Data, err = io.ReadAll(reader)
	if err != nil {
		t.Fatalf("failed to read bytes from Data Frame, err: %s", err)
	}

	if !bytes.Equal(df.Data, decodedDataFrame.Data) {
		t.Errorf("Decoded data do not match: expected %v, got %v", df.Data, decodedDataFrame.Data)
	}
}

func TestDecodeReservedFrameType(t *testing.T) {
	reservedFrame := ReservedFrame{
		FrameId: 0xFF,
		Length:  10,
	}

	encoded, err := reservedFrame.Encode()
	if err != nil {
		t.Fatalf("Failed to encode ReservedFrame: %v", err)
	}

	reader := bytes.NewReader(encoded)

	parser := NewFrameParser(reader)

	frame, err := parser.ParseNextFrame()
	if err != nil {
		t.Fatalf("Failed to decode DataFrame: %v", err)
	}

	decodedReservedFrame, ok := frame.(*ReservedFrame)
	if !ok {
		t.Fatalf("Frame Parser returned incorrect type")
	}

	if decodedReservedFrame.Length != reservedFrame.Length {
		t.Errorf(
			"Decoded data length did not match: expected %d, got %v",
			decodedReservedFrame.Length,
			reservedFrame.Length,
		)
	}
}

func TestDecodeDataFrameInsufficientData(t *testing.T) {
	buf := &bytes.Buffer{}
	encodedType := encodeVarint(FrameData)
	_, err := buf.Write(encodedType)
	if err != nil {
		t.Fatalf("failed to write frame type")
	}
	encodedLength := encodeVarint(4)
	_, err = buf.Write(encodedLength)
	if err != nil {
		t.Fatalf("failed to write frame length")
	}
	buf.Write([]byte{0x01, 0x02, 0x03})

	reader := bytes.NewReader(buf.Bytes())

	parser := NewFrameParser(reader)
	frame, err := parser.ParseNextFrame()
	if err != nil {
		t.Fatalf("Failed to decode type and lenght of Data Frame")
	}
	realFrame, ok := frame.(*DataFrame)
	if !ok {
		t.Fatalf("parser return Frame different from Data Frame")
	}

	_, err = io.CopyN(io.Discard, reader, int64(realFrame.Length))
	if err == nil {
		t.Fatalf("Expected error when decoding DataFrame with EOF signal")
	}
}

func TestDecodeHeadersFrame(t *testing.T) {
	var testData = []struct {
		input []byte
		want  HeadersFrame
	}{
		{[]byte{
			0x1, 0x2a, 0x0, 0x0, 0x50, 0x8f, 0xb, 0xec, 0xae, 0x17,
			0x1d, 0x5c, 0x20, 0x2, 0xe1, 0x0, 0x2e, 0x34, 0xd3, 0x2c,
			0xff, 0xd1, 0xc1, 0xd7, 0x5f, 0x10, 0x83, 0x9b, 0xd9, 0xab,
			0x5f, 0x50, 0x8b, 0xed, 0x69, 0x88, 0xb4, 0xc7, 0x53, 0x1e,
			0xfd, 0xfa, 0xd8, 0x67,
		}, HeadersFrame{
			Length: 42,
			Headers: []byte{
				0x0, 0x0, 0x50, 0x8f, 0xb, 0xec, 0xae, 0x17, 0x1d, 0x5c,
				0x20, 0x2, 0xe1, 0x0, 0x2e, 0x34, 0xd3, 0x2c, 0xff, 0xd1,
				0xc1, 0xd7, 0x5f, 0x10, 0x83, 0x9b, 0xd9, 0xab, 0x5f, 0x50,
				0x8b, 0xed, 0x69, 0x88, 0xb4, 0xc7, 0x53, 0x1e, 0xfd, 0xfa,
				0xd8, 0x67,
			},
		}},
		{
			[]byte{
				0x1, 0x34, 0x0, 0x0, 0xd9, 0x5f, 0x1d, 0x92, 0x49, 0x7c, 0xa5,
				0x8a, 0xe8, 0x19, 0xaa, 0xfb, 0x50, 0x93, 0x8e, 0xc4, 0x15,
				0x30, 0x5a, 0x99, 0x56, 0x7b, 0x56, 0x96, 0xdd, 0x6d, 0x5f,
				0x4a, 0x9, 0xb5, 0x21, 0xb6, 0x65, 0x4, 0x1, 0x34, 0xa0, 0x5c,
				0xb8, 0x6, 0xee, 0x32, 0xca, 0x98, 0xb4, 0x6f, 0x54, 0x82,
				0x68, 0x5f,
			},
			HeadersFrame{
				Length: 52,
				Headers: []byte{
					0x0, 0x0, 0xd9, 0x5f, 0x1d, 0x92, 0x49, 0x7c, 0xa5, 0x8a,
					0xe8, 0x19, 0xaa, 0xfb, 0x50, 0x93, 0x8e, 0xc4, 0x15, 0x30,
					0x5a, 0x99, 0x56, 0x7b, 0x56, 0x96, 0xdd, 0x6d, 0x5f, 0x4a,
					0x9, 0xb5, 0x21, 0xb6, 0x65, 0x4, 0x1, 0x34, 0xa0, 0x5c, 0xb8,
					0x6, 0xee, 0x32, 0xca, 0x98, 0xb4, 0x6f, 0x54, 0x82, 0x68, 0x5f,
				},
			},
		},
	}

	testFrames(t, testData)
}

func TestDecodeSettingsFrame(t *testing.T) {
	var testData = []struct {
		input []byte
		want  SettingsFrame
	}{
		{[]byte{0x4, 0x2, 0x8, 0x1},
			SettingsFrame{
				Length: 2,
				Settings: map[uint64]uint64{
					ExtendedConnect: 1,
				},
			}},
	}

	testFrames(t, testData)
}

func TestDecodeDataFrame(t *testing.T) {
	var testData = []struct {
		input []byte
		want  DataFrame
	}{
		{[]byte{
			0x0, 0x2a, 0x54, 0x68, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65,
			0x20, 0x69, 0x73, 0x3a, 0x20, 0x53, 0x75, 0x6e, 0x2c, 0x20,
			0x32, 0x35, 0x20, 0x41, 0x75, 0x67, 0x20, 0x32, 0x30, 0x32,
			0x34, 0x20, 0x31, 0x36, 0x3a, 0x30, 0x35, 0x3a, 0x33, 0x33,
			0x20, 0x55, 0x54, 0x43,
		},
			DataFrame{
				Length: 42,
				Data: []byte{
					0x54, 0x68, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20,
					0x69, 0x73, 0x3a, 0x20, 0x53, 0x75, 0x6e, 0x2c, 0x20,
					0x32, 0x35, 0x20, 0x41, 0x75, 0x67, 0x20, 0x32, 0x30,
					0x32, 0x34, 0x20, 0x31, 0x36, 0x3a, 0x30, 0x35, 0x3a,
					0x33, 0x33, 0x20, 0x55, 0x54, 0x43,
				},
			}},
	}

	testDataFrames(t, testData)
}

func testDataFrames(t *testing.T, tests []struct {
	input []byte
	want  DataFrame
}) {
	for _, test := range tests {
		reader := bytes.NewReader(test.input)
		parser := NewFrameParser(reader)
		frame, err := parser.ParseNextFrame()
		if err != nil {
			t.Fatalf("Failed to decode Data Frame: err: %s", err)
		}
		realFrame, ok := frame.(*DataFrame)
		if !ok {
			t.Fatalf("Frame Parser returned incorrect type")
		}

		// NOTE: passing this responsability is ugly, but in the required timeframe this will do
		realFrame.Data, err = io.ReadAll(reader)
		if err != nil {
			t.Fatalf("failed to read bytes from Data Frame, err: %s", err)
		}

		if equal := reflect.DeepEqual(*realFrame, test.want); !equal {
			t.Fatalf("expected %+v, got %+v", test.want, *realFrame)
		}

	}
}

func testFrames[T Frame](t *testing.T, tests []struct {
	input []byte
	want  T
}) {

	for _, test := range tests {
		reader := bytes.NewReader(test.input)
		parser := NewFrameParser(reader)
		frame, err := parser.ParseNextFrame()
		if err != nil {
			t.Fatalf("Failed to decode %s: err: %s", reflect.TypeOf(test.want).Name(), err)
		}
		realFrame, ok := frame.(*T)
		if !ok {
			t.Fatalf("Frame Parser returned incorrect type")
		}
		if equal := reflect.DeepEqual(*realFrame, test.want); !equal {
			t.Fatalf("expected %+v, got %+v", test.want, *realFrame)
		}
	}
}
