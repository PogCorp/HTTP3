package main

import (
	"bytes"
	"fmt"
	"log"
)

func main() {
	// Teste de codificação e decodificação de HEADERS frame
	fmt.Println("Testando HEADERS Frame...")
	testHeadersFrame()

	// Teste de codificação e decodificação de DATA frame
	fmt.Println("Testando DATA Frame...")
	testDataFrame()

	// Teste de codificação e decodificação de SETTINGS frame
	fmt.Println("Testando SETTINGS Frame...")
	testSettingsFrame()
}

func testHeadersFrame() {
	// Cria um HeadersFrame de exemplo
	originalFrame := &HeadersFrame{
		Headers: []byte("example-headers"),
	}

	// Codifica o frame
	encodedData, err := originalFrame.Encode()
	if err != nil {
		log.Fatalf("Erro ao codificar HeadersFrame: %v", err)
	}

	// Decodifica o frame
	decodedFrame := &HeadersFrame{}
	err = decodedFrame.Decode(encodedData)
	if err != nil {
		log.Fatalf("Erro ao decodificar HeadersFrame: %v", err)
	}

	// Verifica se os dados foram preservados
	if !bytes.Equal(originalFrame.Headers, decodedFrame.Headers) {
		fmt.Printf("Erro: Headers não correspondem.\nOriginal: %v\nDecodificado: %v\n", originalFrame.Headers, decodedFrame.Headers)
	} else {
		fmt.Println("HeadersFrame teste passou.")
	}
}

func testDataFrame() {
	// Cria um DataFrame de exemplo
	originalFrame := &DataFrame{
		Data: []byte("example-data"),
	}

	// Codifica o frame
	encodedData, err := originalFrame.Encode()
	if err != nil {
		log.Fatalf("Erro ao codificar DataFrame: %v", err)
	}

	// Decodifica o frame
	decodedFrame := &DataFrame{}
	err = decodedFrame.Decode(encodedData)
	if err != nil {
		log.Fatalf("Erro ao decodificar DataFrame: %v", err)
	}

	// Verifica se os dados foram preservados
	if !bytes.Equal(originalFrame.Data, decodedFrame.Data) {
		fmt.Printf("Erro: Data não corresponde.\nOriginal: %v\nDecodificado: %v\n", originalFrame.Data, decodedFrame.Data)
	} else {
		fmt.Println("DataFrame teste passou.")
	}
}

func testSettingsFrame() {
	// Cria um SettingsFrame de exemplo com pares chave-valor
	originalFrame := &SettingsFrame{
		Settings: map[uint16]uint64{
			0x1: 0x100,
			0x2: 0x200,
		},
	}

	// Codifica o frame
	encodedData, err := originalFrame.Encode()
	if err != nil {
		log.Fatalf("Erro ao codificar SettingsFrame: %v", err)
	}

	// Decodifica o frame
	decodedFrame := &SettingsFrame{}
	err = decodedFrame.Decode(encodedData)
	if err != nil {
		log.Fatalf("Erro ao decodificar SettingsFrame: %v", err)
	}

	// Verifica se os pares chave-valor foram preservados
	for k, v := range originalFrame.Settings {
		if decodedFrame.Settings[k] != v {
			fmt.Printf("Erro: Configuração chave %v não corresponde.\nOriginal: %v\nDecodificado: %v\n", k, v, decodedFrame.Settings[k])
			return
		}
	}

	fmt.Println("SettingsFrame teste passou.")
}

