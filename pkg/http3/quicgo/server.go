package quicgo

import (
	"crypto/tls"
	"net/http"
	"poghttp3/pkg/http3"
	qpack "poghttp3/pkg/qpack/quicgo"
	"poghttp3/pkg/quic/quicgo"
)

func ConfigureTLSConfig(tlsConf *tls.Config) *tls.Config {
	return &tls.Config{
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			config := tlsConf
			if tlsConf.GetConfigForClient != nil {
				clientConfig, err := tlsConf.GetConfigForClient(ch)
				if err != nil {
					return nil, err
				}
				if clientConfig != nil {
					config = clientConfig
				}
			}
			if config == nil {
				return nil, nil
			}

			config = tlsConf.Clone()
			config.NextProtos = []string{http3.ALPNH3Protocol}
			return config, nil
		},
	}
}

func ListenAndServeTLS(addr, certFile, keyFile string, handler http.Handler) error {
	decoderFactory := &qpack.QuicGoQpackFactory{}
	server := http3.NewServer(addr, decoderFactory, handler)
	certficate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	tlsconfig := ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{certficate}})
	quicServer, err := quicgo.NewQuicGoServerTLS(addr, tlsconfig, server)
	if err != nil {
		return err
	}

	return quicServer.Listen()
}
