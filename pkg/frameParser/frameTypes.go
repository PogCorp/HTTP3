package frameparser

// defining the frame types according to RFC 9114
const (
	FrameTypeHeaders  uint8 = 0x01
	FrameTypeData     uint8 = 0x00
	FrameTypeSettings uint8 = 0x04
	FrameTypeGoAway   uint8 = 0x07
)

// Frame layout according to RFC 9114

/*
frame{
	Type(i)
	Length(i)
	Payload(..)
}
*/

// basic frame interface

type Frame interface {
	Type() uint8
	Length() uint64
	// the theoretical max defined by RFC 9000  is 2.pow(62-1), hence uint64
}

// ensure every frame type implements the frame interface

var _ Frame = (*HeadersFrame)(nil)
var _ Frame = (*DataFrame)(nil)
var _ Frame = (*SettingsFrame)(nil)
var _ Frame = (*GoAwayFrame)(nil)

// ====== HEADERS FRAME ======

type HeadersFrame struct {
	FrameLength uint64
	Headers     []byte // compressed headers using QPACK
}

func (hf *HeadersFrame) Type() uint8 {
	return FrameTypeHeaders
}

func (hf *HeadersFrame) Length() uint64 {
	return uint64(len(hf.Headers))
}

// ====== DATA FRAME ======

type DataFrame struct {
	FrameLength uint64
	Data        []byte
}

func (df *DataFrame) Type() uint8 {
	return FrameTypeData
}

func (df *DataFrame) Length() uint64 {
	return uint64(len(df.Data))
}

// ====== SETTINGS FRAME ======

type SettingsFrame struct {
	Settings map[uint16]uint64 //key-value pairs for HTTP/3 settings
}

func (sf *SettingsFrame) Type() uint8 {
	return FrameTypeSettings
}

func (sf *SettingsFrame) Length() uint64 {
	return uint64(len(sf.Settings) * (2 + 8))
	//each setting is 2 bytes (the key) plus 8 bytes (value)
}

// ====== GOAWAY FRAME ======

type GoAwayFrame struct {
	StreamID uint64 // the last stream ID that the server will process
}

func (gf *GoAwayFrame) Type() uint8 {
	return FrameTypeGoAway
}

func (gf *GoAwayFrame) Length() uint64 {
	return 8 // this is the fixed length for the GOAWAY frame, since it represnts a stream StreamID
	// RFC 9000: "A stream ID is a 62 bit integer".
	//The other two bits are the stream identifiers
}
