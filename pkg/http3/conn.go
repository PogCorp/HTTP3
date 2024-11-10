package http3

import (
	"poghttp3/pkg/qpack"
	adapter "poghttp3/pkg/quic"
	"sync/atomic"
)

type connection struct {
	receivedControl      atomic.Bool
	receivedQPackEncoder atomic.Bool
	settings             Settings
	qpackDecoder         qpack.QpackApi

	decodeStream  adapter.QuicUniStream
	controlStream adapter.QuicUniStream
}

// TODO: constructor to start things
