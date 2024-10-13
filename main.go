package main

import (
	"bytes"
	"fmt"
	adapter "poghttp3/pkg/qpack"
	quicGoAdapter "poghttp3/pkg/qpack/quicgo"
)

func main() {
	encoder := quicGoAdapter.NewQuicGoQpackEncoder()

	headers := []adapter.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/index.html"},
		{Name: ":authority", Value: "www.example.com"},
		{Name: "accept", Value: "text/html"},
		{Name: "user-agent", Value: "Go-http-client/1.1"},
	}

	buf := bytes.NewBuffer(nil)

	if err := encoder.Encode(buf, headers...); err != nil {
		fmt.Printf("[encoder.Encode] returned error: %+v\n", err)
		return
	}

	fmt.Printf("Encoded Headers: %x\n", buf.Bytes())

	headerFields, err := encoder.Decode(buf.Bytes())
	if err != nil {
		fmt.Printf("[encoder.Decode] returned error: %+v\n", err)
		return
	}

	for _, headerField := range headerFields {
		fmt.Printf("%s: %s\n", headerField.Name, headerField.Value)
	}
}
