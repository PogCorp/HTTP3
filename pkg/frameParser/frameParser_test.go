package frameparser

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FIX: change parameters of decode to io.Reader
//		certify that this tests pass

func TestEncodeDecodeHeadersFrame(t *testing.T) {
	hf := &HeadersFrame{
		Headers: []byte("Test Headers"),
	}

	encoded, err := hf.Encode()
	if err != nil {
		t.Fatalf("Failed to encode HeadersFrame: %v", err)
	}

	reader := bytes.NewReader(encoded)

	var decodedHeadersFrame HeadersFrame
	if err := decodedHeadersFrame.Decode(reader); err != nil {
		t.Fatalf("Failed to decode HeadersFrame: %v", err)
	}

	if !bytes.Equal(hf.Headers, decodedHeadersFrame.Headers) {
		t.Errorf("Decoded headers do not match: expected %v, got %v", hf.Headers, decodedHeadersFrame.Headers)
	}
}

func TestEncodeDecodeDataFrame(t *testing.T) {
	df := &DataFrame{
		Data: []byte("Hello, HTTP/3"),
	}

	encoded, err := df.Encode()
	if err != nil {
		t.Fatalf("Failed to encode DataFrame: %v", err)
	}

	reader := bytes.NewReader(encoded)

	var decodedDataFrame DataFrame
	if err := decodedDataFrame.Decode(reader); err != nil {
		t.Fatalf("Failed to decode DataFrame: %v", err)
	}

	if !bytes.Equal(df.Data, decodedDataFrame.Data) {
		t.Errorf("Decoded data do not match: expected %v, got %v", df.Data, decodedDataFrame.Data)
	}
}

func TestDecodeUnexpectedFrameType(t *testing.T) {
	invalidFrame := []byte{0xFF}

	reader := bytes.NewReader(invalidFrame)

	var decodedHeadersFrame HeadersFrame
	err := decodedHeadersFrame.Decode(reader)
	if err == nil {
		t.Fatalf("Expected error when decoding invalid frame type, got none")
	}
}

func TestDecodeDataFrameInsufficientData(t *testing.T) {
	invalidDataFrame := make([]byte, 5)
	binary.BigEndian.PutUint64(invalidDataFrame, FrameData)
	invalidDataFrame = append(invalidDataFrame, byte(0x01))

	reader := bytes.NewReader(invalidDataFrame)

	var decodedDataFrame DataFrame
	err := decodedDataFrame.Decode(reader)
	if err == nil {
		t.Fatalf("Expected error when decoding DataFrame with insufficient data, got none")
	}
}
