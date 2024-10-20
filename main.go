package main

import (
	"poghttp3/pkg/http3/server"
	"poghttp3/pkg/http3/server/utils"
	adapter "poghttp3/pkg/quic"
)

func main() {
	var tlsConfig = utils.GenerateTLSConfig()

	var server = server.NewServer("localhost", 4242, tlsConfig, adapter.QuicGoAdapterImplementaion)

	server.Listen()
}
