package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	qpack "poghttp3/pkg/qpack"
	quicGoAdapter "poghttp3/pkg/qpack/quicgo"
)

type FrameParser struct {
	reader       io.Reader
	qpackDecoder qpack.QpackApi
}

type FrameParserOption func(*FrameParser)

func WithQpackApi(qpackApi qpack.QpackApi) FrameParserOption {
	return func(fp *FrameParser) {
		fp.qpackDecoder = qpackApi
	}
}

var DefaultQpackEncoder qpack.QpackApi = quicGoAdapter.NewQuicGoQpackEncoder()

// frame parser initialization and bindiding with a stream
// just assuming the stream
func NewFrameParser(r io.Reader, opts ...FrameParserOption) *FrameParser {
	frameParser := &FrameParser{
		reader:       r,
		qpackDecoder: DefaultQpackEncoder,
	}

	for _, opt := range opts {
		opt(frameParser)
	}

	return frameParser
}

// read stream and parse multiple frames
func (p *FrameParser) ParseFrames() error {
	for {
		// read the frame type (the first byte)
		var frameType uint8
		if err := binary.Read(p.reader, binary.BigEndian, &frameType); err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Println("End of File Received")
				return nil
			}
			return fmt.Errorf("failed to read byte data, got err: %w", err)
		}

		// read the length field
		length, err := p.readFrameLength()
		if err != nil {
			return fmt.Errorf("unable to acquire frame lenght, got err: %w", err)
		}

		// read the payload according to its length
		payload := make([]byte, length)
		if _, err := io.ReadFull(p.reader, payload); err != nil {
			return fmt.Errorf("failed to read frame data, got err: %w", err)
		}

		// parse frame according to it's type
		switch frameType {
		case FrameTypeHeaders:
			headersFrame := &HeadersFrame{}
			if err := headersFrame.Decode(payload); err != nil {
				return fmt.Errorf("failed to decode HeadersFrame, got err: %w", err)
			}
			fmt.Printf("HEADERS Frame decodificado: %s\n", headersFrame.Headers)

			headerFields, err := p.qpackDecoder.Decode(headersFrame.Headers)
			if err != nil {
				fmt.Printf("[encoder.Decode] returned error: %+v\n", err)
				return fmt.Errorf("failed to decode headers using qpack decoder, got err: %w", err)
			}

			for _, hf := range headerFields {
				fmt.Printf("KEY: %s VALUE: %s\n", hf.Name, hf.Value)
			}

		case FrameTypeData:
			dataFrame := &DataFrame{}
			if err := dataFrame.Decode(payload); err != nil {
				return fmt.Errorf("failed to decode DataFrame, got err: %w", err)
			}
			fmt.Printf("Decoded DataFrame: %s\n", dataFrame.Data)

		case FrameTypeSettings:
			settingsFrame := &SettingsFrame{}
			if err := settingsFrame.Decode(payload); err != nil {
				return fmt.Errorf("failed to decode SettingsFrame, got err: %w", err)
			}
			fmt.Println("SettingsFrame decoded")

		default:
			return fmt.Errorf("unknown frame Type: %d", frameType)
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
