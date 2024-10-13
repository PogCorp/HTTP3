package adapter

import "io"

type QpackApi interface {
	Encode(buffer io.Writer, headerFields ...HeaderField) error
	Decode(data []byte) ([]HeaderField, error)
}

type HeaderField struct {
	Name  string
	Value string
}
