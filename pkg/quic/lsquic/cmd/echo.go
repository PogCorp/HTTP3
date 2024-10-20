package main

import (
	"log"
	lsquic "poghttp3/pkg/quic/lsquic"
)

func main() {
	api := lsquic.NewQuicApi()
	lsquicServer, err := lsquic.NewQuicServer("localhost:8080", "../certs/priv.key", "../certs/cert.crt", api)
	if err != nil {
		log.Println("failed to start lsquic server", err)
		return
	}
	if err := lsquicServer.Listen(); err != nil {
		log.Println("failed on server listen", err)
	}
}
