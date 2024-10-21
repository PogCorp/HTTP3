package frameparser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"time"
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

func decodeVarint(r io.Reader) (value uint64, lenght uint64, err error) {
	var b [1]byte
	if _, err = r.Read(b[:1]); err != nil {
		return 0, 0, err
	}

	switch lenghtBits := b[0] & 0xC0; lenghtBits {
	case 0x00:
		return uint64(b[0]), 1, nil
	case 0x40:
		var n [1]byte
		if _, err = r.Read(n[:1]); err != nil {
			return
		}
		return uint64(b[0]&0x3F)<<8 + uint64(n[0]), 2, nil
	case 0x80:
		var n [3]byte
		if _, err = r.Read(n[:3]); err != nil {
			return
		}
		return uint64(b[0]&0x3F)<<24 + uint64(n[0])<<16 + uint64(n[1])<<8 + uint64(n[2]), 4, nil
	case 0xC0:
		var n [7]byte
		if _, err = r.Read(n[:7]); err != nil {
			return
		}
		return uint64(b[0]&0x3F)<<56 + uint64(n[0])<<48 + uint64(n[1])<<40 + uint64(n[2])<<32 + uint64(n[3])<<24 + uint64(n[4])<<16 + uint64(n[5])<<8 + uint64(n[6]), 8, nil
	}
	return 0, 0, fmt.Errorf("invalid varint encoding")
}

// -------------------- HEADERS FRAME OPERATIONS ----------------------
func (hf *HeadersFrame) Encode() ([]byte, error) {
	buf := &bytes.Buffer{}

	// encodes the frame type
	frameType := encodeVarint(FrameHeaders) // HACK: constants can be put here, so no operation needs to be done
	_, err := buf.Write(frameType)
	if err != nil {
		return nil, err
	}

	// encodes the payload length using varint
	lengthBytes := encodeVarint(hf.Length())
	buf.Write(lengthBytes)

	// Writes the compressed headers
	buf.Write(hf.Headers)

	return buf.Bytes(), nil
}

func (hf *HeadersFrame) Decode(reader io.Reader) error {

	// Reads the payload
	hf.Headers = make([]byte, hf.FrameLength)
	if _, err := io.ReadFull(reader, hf.Headers); err != nil {
		return err
	}

	return nil
}

// the workflow is constant. Encode frame type, encode the payload length using varint, write the data in the
// []byte (payload is already in binary)
// decode frame type, decode payload lenght, use payload length to read the data

// -------------------- DATA FRAME OPERATIONS ----------------------
func (df *DataFrame) Encode() ([]byte, error) {
	if df.FrameLength <= 0 {
		return nil, fmt.Errorf("no payload to encode DataFrame")
	}

	buf := &bytes.Buffer{}

	frameType := encodeVarint(FrameData)
	_, err := buf.Write(frameType)
	if err != nil {
		return nil, err
	}

	lengthBytes := encodeVarint(df.Length())
	_, err = buf.Write(lengthBytes)
	if err != nil {
		return nil, err
	}

	_, err = buf.Write(df.Data)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (df *DataFrame) Decode(reader io.Reader) error {

	df.Data = make([]byte, df.FrameLength)
	if _, err := io.ReadFull(reader, df.Data); err != nil {
		return err
	}

	return nil
}

// -------------------- SETTINGS FRAME OPERATIONS ----------------------
func (sf *SettingsFrame) Encode() ([]byte, error) {
	if len(sf.Settings) <= 0 {
		return nil, fmt.Errorf("no settings to encode SettingsFrame")
	}
	buf := &bytes.Buffer{}

	frameType := encodeVarint(FrameSettings)
	_, err := buf.Write(frameType)
	if err != nil {
		return nil, err
	}

	lengthBytes := encodeVarint(sf.Length())
	_, err = buf.Write(lengthBytes)
	if err != nil {
		return nil, err
	}

	for k, v := range sf.Settings {
		buf.Write(encodeVarint(uint64(k)))
		buf.Write(encodeVarint(v))
	}

	return buf.Bytes(), nil
}

func (sf *SettingsFrame) Decode(reader io.Reader) error {

	// Instantiating the config map
	sf.Settings = make(map[uint16]uint64)

	// Reads each key-value pair of the payload
	bytesRead := uint64(0)
	for bytesRead < sf.FrameLength {

		key, keyLen, err := decodeVarint(reader)
		if err != nil {
			return err
		}

		bytesRead += keyLen

		value, valueLen, err := decodeVarint(reader)
		if err != nil {
			return err
		}
		bytesRead += valueLen

		// Stores the key-value pay in the map
		sf.Settings[uint16(key)] = value
	}

	if bytesRead != sf.FrameLength {
		return fmt.Errorf("malformed Settings Frame, length field not equal frame payload size")
	}

	return nil
}

func (rf *ReservedFrame) Encode() ([]byte, error) {
	if rf.FrameLength <= 0 {
		return nil, fmt.Errorf("no length to encode ReservedFrame")
	}
	data := make([]byte, rf.FrameLength)
	now := time.Now()
	nowBinary, err := now.MarshalBinary()
	if err != nil {
		nowBinary = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456") // default to this seed instead
	}
	chacha := rand.NewChaCha8([32]byte(nowBinary))
	_, err = chacha.Read(data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (rf *ReservedFrame) Decode(reader io.Reader) error {

	if _, err := io.CopyN(io.Discard, reader, int64(rf.FrameLength)); err != nil {
		return err
	}
	return nil
}

// TODO: missing GoAway decoder and encoder
