package main

import (
	"bytes"
	"fmt"
	"log"
)

func main() {
	// test encoding and decoding from HEADERS frame
	fmt.Println("Testando HEADERS Frame...")
	testHeadersFrame()

	// test encoding and decoding from DATA frame
	fmt.Println("Testando DATA Frame...")
	testDataFrame()

	// test encoding and decoding from SETTINGS frame
	fmt.Println("Testando SETTINGS Frame...")
	testSettingsFrame()
}

func testHeadersFrame() {
	// create a HeadersFrame
	originalFrame := &HeadersFrame{
		Headers: []byte("example-headers"),
	}

	// encode frame
	encodedData, err := originalFrame.Encode()
	if err != nil {
		log.Fatalf("Erro ao codificar HeadersFrame: %v", err)
	}

	// decode frame
	decodedFrame := &HeadersFrame{}
	err = decodedFrame.Decode(encodedData)
	if err != nil {
		log.Fatalf("Erro ao decodificar HeadersFrame: %v", err)
	}

	// verify header preservation
	if !bytes.Equal(originalFrame.Headers, decodedFrame.Headers) {
		fmt.Printf("Erro: Headers não correspondem.\nOriginal: %v\nDecodificado: %v\n", originalFrame.Headers, decodedFrame.Headers)
	} else {
		fmt.Println("HeadersFrame teste passou.")
	}
}

func testDataFrame() {
	// create a DataFrame
	originalFrame := &DataFrame{
		Data: []byte("example-data"),
	}

	// encode frame
	encodedData, err := originalFrame.Encode()
	if err != nil {
		log.Fatalf("Erro ao codificar DataFrame: %v", err)
	}

	// decode frame
	decodedFrame := &DataFrame{}
	err = decodedFrame.Decode(encodedData)
	if err != nil {
		log.Fatalf("Erro ao decodificar DataFrame: %v", err)
	}

	// verify if data was preserved
	if !bytes.Equal(originalFrame.Data, decodedFrame.Data) {
		fmt.Printf("Erro: Data não corresponde.\nOriginal: %v\nDecodificado: %v\n", originalFrame.Data, decodedFrame.Data)
	} else {
		fmt.Println("DataFrame teste passou.")
	}
}

func testSettingsFrame() {
	// create SettingsFrame with key values pairs
	originalFrame := &SettingsFrame{
		Settings: map[uint16]uint64{
			0x1: 0x100,
			0x2: 0x200,
		},
	}

	// encode frame
	encodedData, err := originalFrame.Encode()
	if err != nil {
		log.Fatalf("Erro ao codificar SettingsFrame: %v", err)
	}

	// decode frame
	decodedFrame := &SettingsFrame{}
	err = decodedFrame.Decode(encodedData)
	if err != nil {
		log.Fatalf("Erro ao decodificar SettingsFrame: %v", err)
	}

	// verify if pairs were preserved
	for k, v := range originalFrame.Settings {
		if decodedFrame.Settings[k] != v {
			fmt.Printf("Erro: Configuração chave %v não corresponde.\nOriginal: %v\nDecodificado: %v\n", k, v, decodedFrame.Settings[k])
			return
		}
	}

	fmt.Println("SettingsFrame teste passou.")
}
