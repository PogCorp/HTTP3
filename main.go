package main

import (
	"poghttp3/pkg/quic/quicgo"
)

func main() {
	var adapter = quicgo.NewQuicGoAdapter()

	var server = quicgo.NewQuickGoServer(adapter)

	server.Listen()
}
