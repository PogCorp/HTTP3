package frameparser

type FrameType = uint64
type Setting = uint64

// defining the frame types according to RFC 9114
const (
	FrameHeaders  FrameType = 0x01
	FrameData     FrameType = 0x00
	FrameSettings FrameType = 0x04
	FrameGoAway   FrameType = 0x07
)

// Available Settings for SettingsFrame
const (
	MaxFieldSectionSize Setting = 0x06 // section 7.2.4.1 from RFC 9114
	// this value should be only 0 or 1, meaning deactivated and activated, respectivelly
	Datagrams Setting = 0x33
	// this value should be only 0 or 1, meaning deactivated and activated, respectivelly
	ExtendedConnect Setting = 0x8
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
}

// ensure every frame type implements the frame interface

var _ Frame = (*HeadersFrame)(nil)
var _ Frame = (*DataFrame)(nil)
var _ Frame = (*SettingsFrame)(nil)
var _ Frame = (*GoAwayFrame)(nil)

// ====== HEADERS FRAME ======

// NOTE: this frame could have a key-value pair structure instead of just bytes
type HeadersFrame struct {
	Length  uint64
	Headers []byte // compressed headers using QPACK
}

// ====== DATA FRAME ======

type DataFrame struct {
	Length uint64
	Data   []byte
}

// ====== SETTINGS FRAME ======

type SettingsFrame struct {
	Length   uint64
	Settings map[Setting]uint64 //key-value pairs for HTTP/3 settings
}

// ====== GOAWAY FRAME ======

type GoAwayFrame struct {
	Length   uint64
	StreamID uint64 // the last stream ID that the server will process
}

// ====== Reserved FRAMES ======

type ReservedFrame struct {
	FrameId FrameType
	Length  uint64
}
