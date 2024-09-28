package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type FrameParser struct {
	reader io.Reader
}

// frame parser initialization and bindiding with a stream
// just assuming the stream
func NewFrameParser(r io.Reader) *FrameParser {
	return &FrameParser{
		reader: r,
	}
}

// read stream and parse multiple frames
func (p *FrameParser) ParseFrames() error {
	for {
		// read the frame type (the first byte)
		var frameType uint8
		if err := binary.Read(p.reader, binary.BigEndian, &frameType); err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Println("Fim dos dados.")
				return nil
			}
			return fmt.Errorf("erro ao ler tipo do frame: %w", err)
		}

		// read the length field
		length, err := p.readFrameLength()
		if err != nil {
			return fmt.Errorf("erro ao ler comprimento do frame: %w", err)
		}

		// read the payload according to its length
		payload := make([]byte, length)
		if _, err := io.ReadFull(p.reader, payload); err != nil {
			return fmt.Errorf("erro ao ler payload do frame: %w", err)
		}

		// parse frame according to it's type
		switch frameType {
		case FrameTypeHeaders:
			headersFrame := &HeadersFrame{}
			if err := headersFrame.Decode(payload); err != nil {
				return fmt.Errorf("erro ao decodificar HEADERS frame: %w", err)
			}
			fmt.Printf("HEADERS Frame decodificado: %s\n", headersFrame.Headers)

		case FrameTypeData:
			dataFrame := &DataFrame{}
			if err := dataFrame.Decode(payload); err != nil {
				return fmt.Errorf("erro ao decodificar DATA frame: %w", err)
			}
			fmt.Printf("DATA Frame decodificado: %s\n", dataFrame.Data)

		case FrameTypeSettings:
			settingsFrame := &SettingsFrame{}
			if err := settingsFrame.Decode(payload); err != nil {
				return fmt.Errorf("erro ao decodificar SETTINGS frame: %w", err)
			}
			fmt.Println("SETTINGS Frame decodificado.")

		default:
			return fmt.Errorf("tipo de frame desconhecido: %d", frameType)
		}
	}
}

func (p *FrameParser) readFrameLength() (uint64, error) {
	var length uint16
	if err := binary.Read(p.reader, binary.BigEndian, &length); err != nil {
		return 0, err
	}
	return uint64(length), nil
}
