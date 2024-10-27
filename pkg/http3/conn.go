package http3

import (
	adapter "poghttp3/pkg/quic"
	"sync/atomic"
)

type connection struct {
	receivedControl      atomic.Bool
	receivedQPackEncoder atomic.Bool

	decodeStream  adapter.QuicUniStream
	controlStream adapter.QuicUniStream
}

// TODO: constructor to start things
