package adapter

type QuicAdapter interface {
	OnNewConnection(id []byte)
	OnNewStream(id int64)
	OnCanceledConn(id []byte)
	OnReadStream(id int64, data []byte)
	WriteStream(id int64, data []byte)
	Listen()
}
