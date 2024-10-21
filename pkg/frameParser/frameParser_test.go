package frameparser

import (
	"bytes"
	adapter "poghttp3/pkg/qpack"
	"poghttp3/pkg/qpack/quicgo"
	"testing"
)

// TEST: integration tests that test the interaction of encoding frames and decoding from them back

func TestEncodeDecodeHeadersFrame(t *testing.T) {
	qpack := quicgo.NewQuicGoQpackEncoder()
	buf := &bytes.Buffer{}
	err := qpack.Encode(buf, adapter.HeaderField{Name: "Test Name", Value: "Test Headers"})
	if err != nil {
		t.Fatalf("Failed to encode HeadersField content: %v", err)
	}

	hf := &HeadersFrame{
		FrameLength: uint64(buf.Len()),
		Headers:     buf.Bytes(),
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
		FrameLength: uint64(len(data)),
		Data:        data,
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

	if !bytes.Equal(df.Data, decodedDataFrame.Data) {
		t.Errorf("Decoded data do not match: expected %v, got %v", df.Data, decodedDataFrame.Data)
	}
}

func TestDecodeReservedFrameType(t *testing.T) {
	reservedFrame := ReservedFrame{
		FrameId:     0xFF,
		FrameLength: 10,
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

	if decodedReservedFrame.Length() != reservedFrame.Length() {
		t.Errorf(
			"Decoded data length did not match: expected %d, got %v",
			decodedReservedFrame.Length(),
			reservedFrame.Length(),
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
	_, err = parser.ParseNextFrame()
	if err == nil {
		t.Fatalf("Expected error when decoding DataFrame with EOF signal")
	}
}
