package server

import (
	"crypto/tls"
	"fmt"
	adapter "poghttp3/pkg/quic"
	"poghttp3/pkg/quic/quicgo"
)

type server struct {
	Address            string
	Port               int
	TLSConfig          *tls.Config
	implementationType adapter.QuicAdapterImplementation
	quicServer         adapter.QuicServer
}

var _ (Server) = (*server)(nil)

func newQuicAdapter(quicAdapterImpl adapter.QuicAdapterImplementation) adapter.QuicAdapter {
	if quicAdapterImpl == adapter.QuicGoAdapterImplementaion {
		return quicgo.NewQuicGoAdapter()
	}

	// TODO: add lsquic adapter
	return nil
}

func NewServer(address string, port int, tlsConfig *tls.Config, quicAdapterImpl adapter.QuicAdapterImplementation) Server {
	return &server{
		Address:    address,
		Port:       port,
		TLSConfig:  tlsConfig,
		quicServer: quicgo.NewQuickGoServer(fmt.Sprintf("%s:%d", address, port), tlsConfig, newQuicAdapter(quicAdapterImpl)),
	}
}

func (s *server) Listen() error {
	return s.quicServer.Listen()
}
