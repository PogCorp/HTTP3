package adapter

type QuicAdapter interface {
	onNewConnection(id []byte)
	onNewStream(id int64)
	onCanceledConn(id []byte)
	onReadStream(id int64, data []byte)
	writeStream(id int64, data []byte)
	Listen()
}
