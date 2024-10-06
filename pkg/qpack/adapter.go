package adapter

import "io"

type QpackApi interface {
	Encode(buffer io.Writer, headerFields ...HeaderField) error
	Decode(buffer io.Reader) ([]HeaderField, error)
}

type HeaderField struct {
	Name  string
	Value string
}
