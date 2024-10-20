package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"poghttp3/pkg/http3/server/version"
)

func LoadCertificateFromKeyPair(certFilePath, keyFilePath string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certFilePath, keyFilePath)
}

func ConfigureTLSConfig(tlsConf *tls.Config) *tls.Config {
	return &tls.Config{
		GetConfigForClient: func(ch *tls.ClientHelloInfo) (*tls.Config, error) {
			config := tlsConf
			if tlsConf.GetConfigForClient != nil {
				conf, err := tlsConf.GetConfigForClient(ch)
				if err != nil {
					return nil, err
				}
				if conf != nil {
					config = conf
				}
			}
			if config == nil {
				return nil, nil
			}

			_, _ = tlsConf.DecryptTicket(nil, tls.ConnectionState{})

			config = tlsConf.Clone()
			config.NextProtos = []string{version.ALPNH3Protocol}
			return config, nil
		},
	}
}

func GenerateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}
