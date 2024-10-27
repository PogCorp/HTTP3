package http3

const (
	NoError                  = 0x100
	GeneralProtocolError     = 0x101
	InternalError            = 0x102
	StreamCreationError      = 0x103
	ClosedCriticalStream     = 0x104
	FrameUnexpected          = 0x105
	FrameError               = 0x106
	ExcessiveLoad            = 0x107
	IdError                  = 0x108
	SettingsError            = 0x109
	MissingSettings          = 0x10A
	RequestRejected          = 0x10B
	RequestCancelled         = 0x10C
	RequestIncomplete        = 0x10D
	MessageError             = 0x10E
	ConnectError             = 0x10F
	VersionFallback          = 0x110
	QpackDecompressionFailed = 0x200
	QpackEncoderStreamError  = 0x201
	QpackDecoderStreamError  = 0x202
)
