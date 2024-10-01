package quicgo

import (
	adapter "poghttp3/pkg/quic"

	"github.com/quic-go/quic-go"
)

type QuicGoCID struct {
	*quic.ConnectionID
}

func NewQuicGoCID(connId quic.ConnectionID) adapter.QuicCID {
	return &QuicGoCID{
		&connId,
	}
}
