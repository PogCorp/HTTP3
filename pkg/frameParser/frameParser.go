package frameparser

import (
	"errors"
	"fmt"
	"io"
	"log"
	qpack "poghttp3/pkg/qpack"
)

type FrameParser struct {
	reader       io.Reader
	qpackDecoder qpack.QpackApi
}

// frame parser initialization and bindiding with a stream
// just assuming the stream
func NewFrameParser(r io.Reader, qpack qpack.QpackApi) *FrameParser {
	return &FrameParser{
		reader:       r,
		qpackDecoder: qpack,
	}
}

// read stream and parse multiple frames
func (p *FrameParser) ParseNextFrame() (Frame, error) {
	// read the frame type (the first byte)
	frameType, _, err := decodeVarint(p.reader)
	if err != nil {
		if errors.Is(err, io.EOF) {
			fmt.Println("End of File Received")
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read byte data, got err: %w", err)
	}

	// parse frame according to it's type
	switch frameType {
	case FrameHeaders:
		headersFrame := &HeadersFrame{}
		if err := headersFrame.Decode(p.reader); err != nil {
			return nil, fmt.Errorf("failed to decode HeadersFrame, got err: %w", err)
		}
		fmt.Printf("HEADERS Frame decoded: %s\n", headersFrame.Headers)

		headerFields, err := p.qpackDecoder.Decode(headersFrame.Headers)
		if err != nil {
			fmt.Printf("[encoder.Decode] returned error: %+v\n", err)
			return nil, fmt.Errorf("failed to decode headers using qpack decoder, got err: %w", err)
		}

		for _, hf := range headerFields {
			fmt.Printf("KEY: %s VALUE: %s\n", hf.Name, hf.Value)
		}

		return headersFrame, nil
	case FrameData:
		dataFrame := &DataFrame{}
		if err := dataFrame.Decode(p.reader); err != nil {
			return nil, fmt.Errorf("failed to decode DataFrame, got err: %w", err)
		}
		fmt.Printf("Decoded DataFrame: %s\n", dataFrame.Data)

		return dataFrame, nil
	case FrameSettings:
		settingsFrame := &SettingsFrame{}
		if err := settingsFrame.Decode(p.reader); err != nil {
			return nil, fmt.Errorf("failed to decode SettingsFrame, got err: %w", err)
		}
		fmt.Println("SettingsFrame decoded")

		return settingsFrame, nil

		// TODO: add GoAway Frame case here
	default:
		reservedFrame := &ReservedFrame{}
		if err := reservedFrame.Decode(p.reader); err != nil {
			log.Printf("failed to decode ReservedFrame, got err: %w", err)
		}

		return reservedFrame, nil
	}
}

func (p *FrameParser) readFrameLength() (uint64, error) {
	length, _, err := decodeVarint(p.reader)
	if err != nil {
		return 0, err
	}
	return length, nil
}
