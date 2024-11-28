package http3

import (
	"sync/atomic"

	adapter "github.com/PogCorp/HTTP3/pkg/quic"

	"github.com/PogCorp/HTTP3/pkg/qpack"
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
