package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// varint encoding is used by RFC 9000
// variable encoding allows small integer numbers to be represented in a single or just a few bytes
// which saves space and bandwitdh

// ====== VARINT ENCODING =====

/*
This implements Varint encoding of variable length integers. It adjusts the number of bytes
used to represent a number based on its value, using a minimum number of bytes for small values
and more bytes for larger values. It encodes integers according to the format described in RFC 9000
and it can generate from 1 to 8 bytes depending on the value of n, which is evaluated in the switch

I) if n < 2^6 = 64 (1 << 6), it can be represented in 6 bits, that is, one single byte
   In this case, the value is stored directly in the first byte (buf[0]) and this single byte
   is returned (buf[:1])

II) If n < 2 ^ 14 = 16.384 (1 << 14), it can be represented in 14 bits.
	The number is converted to 16 bits and the 2 most significant bits are set to 01,
    to indicate that 2 bytes are beign used.
    BigEndian.PutUint16 converts the number to 16 bits (2 bytes) in Big-Endian order,
    so that the more significant bytes appear first. 0x4000 is used in the bitwise OR to
	set the 2 bits as 01

All other cases follow the same logic as the explanation above, but with different ranges for n
*/

func encodeVarint(n uint64) []byte {
	var buf [8]byte

	switch {
	case n < 1<<6:
		buf[0] = byte(n)
		return buf[:1]

	case n < 1<<14:
		binary.BigEndian.PutUint16(buf[:], uint16(n)|0x4000)
		return buf[:2]

	case n < 1<<30:
		binary.BigEndian.PutUint32(buf[:], uint32(n)|0x80000000)
		return buf[:4]

	default:
		binary.BigEndian.PutUint64(buf[:], n|0xC000000000000000)
		return buf[:8]
	}
}

func decodeVarint(r io.Reader) (uint64, error) {
	var b [1]byte
	if _, err := r.Read(b[:1]); err != nil {
		return 0, err
	}

	switch lenghtBits := b[0] & 0xC0; lenghtBits {
	case 0x00:
		return uint64(b[0]), nil
	case 0x40:
		var n [1]byte
		if _, err := r.Read(n[:1]); err != nil {
			return 0, err
		}
		return uint64(b[0]&0x3F)<<8 + uint64(n[0]), nil
	case 0x80:
		var n [3]byte
		if _, err := r.Read(n[:3]); err != nil {
			return 0, err
		}
		return uint64(b[0]&0x3F)<<24 + uint64(n[0])<<16 + uint64(n[1])<<8 + uint64(n[2]), nil
	case 0xC0:
		var n [7]byte
		if _, err := r.Read(n[:7]); err != nil {
			return 0, err
		}
		return uint64(b[0]&0x3F)<<56 + uint64(n[0])<<48 + uint64(n[1])<<40 + uint64(n[2])<<32 + uint64(n[3])<<24 + uint64(n[4])<<16 + uint64(n[5])<<8 + uint64(n[6]), nil
	}
	return 0, fmt.Errorf("invalid varint encoding")
}

// -------------------- HEADERS FRAME OPERATIONS ----------------------
func (hf *HeadersFrame) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}

	// encodes the frame type
	if err := binary.Write(buf, binary.BigEndian, FrameTypeHeaders); err != nil {
		return nil, err
	}

	// encodes the payload length using varint
	lengthBytes := encodeVarint(hf.Length())
	buf.Write(lengthBytes)

	// Writes the compressed headers
	//TODO: QPACK compression
	buf.Write(hf.Headers)

	return buf.Bytes(), nil
}

func (hf *HeadersFrame) Decode(data []byte) error {
	reader := bytes.NewReader(data)

	// Decodes the frame type (2 bytes)
	var frameType uint8
	if err := binary.Read(reader, binary.BigEndian, &frameType); err != nil {
		return err
	}
	if frameType != FrameTypeHeaders {
		return fmt.Errorf("expected HEADERS frame, got %d", frameType)
	}

	// Decodes the payload length using varint
	length, err := decodeVarint(reader)
	if err != nil {
		return err
	}

	// Reads the payload
	hf.FrameLength = length
	hf.Headers = make([]byte, length)
	if _, err := io.ReadFull(reader, hf.Headers); err != nil {
		return err
	}

	// TODO: QPACK decompression

	return nil
}

// the workflow is constant. Encode frame type, encode the payload length using varint, write the data in the
// []byte (payload is already in binary)
// decode frame type, decode payload lenght, use payload length to read the data

// -------------------- DATA FRAME OPERATIONS ----------------------
func (df *DataFrame) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}

	if err := binary.Write(buf, binary.BigEndian, FrameTypeData); err != nil {
		return nil, err
	}

	lengthBytes := encodeVarint(df.Length())
	buf.Write(lengthBytes)

	buf.Write(df.Data)

	return buf.Bytes(), nil
}

func (df *DataFrame) Decode(data []byte) error {
	reader := bytes.NewReader(data)

	var frameType uint8
	if err := binary.Read(reader, binary.BigEndian, &frameType); err != nil {
		return err
	}
	if frameType != FrameTypeData {
		return fmt.Errorf("expected DATA frame, got %d", frameType)
	}

	length, err := decodeVarint(reader)
	if err != nil {
		return err
	}

	df.FrameLength = length
	df.Data = make([]byte, length)
	if _, err := io.ReadFull(reader, df.Data); err != nil {
		return err
	}

	return nil
}

// -------------------- SETTINGS FRAME OPERATIONS ----------------------
func (sf *SettingsFrame) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}

	if err := binary.Write(buf, binary.BigEndian, FrameTypeSettings); err != nil {
		return nil, err
	}

	lengthBytes := encodeVarint(sf.Length())
	buf.Write(lengthBytes)

	// TODO: Use varint encoding for the key and the value (super easy, but I forgot)
	for k, v := range sf.Settings {
		if err := binary.Write(buf, binary.BigEndian, k); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.BigEndian, v); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func (sf *SettingsFrame) Decode(data []byte) error {
	reader := bytes.NewReader(data)

	var frameType uint8
	if err := binary.Read(reader, binary.BigEndian, &frameType); err != nil {
		return err
	}
	if frameType != FrameTypeSettings {
		return fmt.Errorf("expected SETTINGS frame, got %d", frameType)
	}

	length, err := decodeVarint(reader)
	if err != nil {
		return err
	}

	// Instantiating the config map
	sf.Settings = make(map[uint16]uint64)

	// Reads each key-value pair of the payload
	bytesRead := uint64(0)
	for bytesRead < length {
		var key uint16
		var value uint64

		// Reads the key (2 bytes)
		if err := binary.Read(reader, binary.BigEndian, &key); err != nil {
			return err
		}
		bytesRead += 2

		// Reads the value (8 bytes)
		if err := binary.Read(reader, binary.BigEndian, &value); err != nil {
			return err
		}
		bytesRead += 8

		// Stores the key-value pay in the map
		sf.Settings[key] = value
	}

	return nil
}
