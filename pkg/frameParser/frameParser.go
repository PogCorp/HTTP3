package frameparser

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

func (p *FrameParser) readFrameType() (uint8, error) {
	var frameType uint8
	if err := binary.Read(p.reader, binary.BigEndian, &frameType); err != nil {
		if errors.Is(err, io.EOF) {
			fmt.Println("End of File Received")
			return 0, nil
		}
		return 0, fmt.Errorf("failed to read byte data, got err: %w", err)
	}

	return frameType, nil
}

func (p *FrameParser) readFrameLength() (uint64, error) {
	var length uint16
	if err := binary.Read(p.reader, binary.BigEndian, &length); err != nil {
		return 0, err
	}
	return uint64(length), nil
}

// read stream and parse multiple frames
func (p *FrameParser) ParseNextFrame() (Frame, error) {
	// read the frame type (the first byte)
	frameType, err := p.readFrameType()
	if err != nil {
		return nil, err
	}

	// read the length field
	length, err := p.readFrameLength()
	if err != nil {
		return nil, fmt.Errorf("unable to acquire frame lenght, got err: %w", err)
	}

	// read the payload according to its length
	payload := make([]byte, length)
	if _, err := io.ReadFull(p.reader, payload); err != nil {
		return nil, fmt.Errorf("failed to read frame data, got err: %w", err)
	}

	// parse frame according to it's type
	switch frameType {
	case FrameTypeHeaders:
		headersFrame := &HeadersFrame{}
		if err := headersFrame.Decode(payload); err != nil {
			return nil, fmt.Errorf("failed to decode HeadersFrame, got err: %w", err)
		}
		fmt.Printf("HEADERS Frame decodificado: %s\n", headersFrame.Headers)

		headerFields, err := p.qpackDecoder.Decode(headersFrame.Headers)
		if err != nil {
			fmt.Printf("[encoder.Decode] returned error: %+v\n", err)
			return nil, fmt.Errorf("failed to decode headers using qpack decoder, got err: %w", err)
		}

		for _, hf := range headerFields {
			fmt.Printf("KEY: %s VALUE: %s\n", hf.Name, hf.Value)
		}

		return headersFrame, nil
	case FrameTypeData:
		dataFrame := &DataFrame{}
		if err := dataFrame.Decode(payload); err != nil {
			return nil, fmt.Errorf("failed to decode DataFrame, got err: %w", err)
		}
		fmt.Printf("Decoded DataFrame: %s\n", dataFrame.Data)

		return dataFrame, nil
	case FrameTypeSettings:
		settingsFrame := &SettingsFrame{}
		if err := settingsFrame.Decode(payload); err != nil {
			return nil, fmt.Errorf("failed to decode SettingsFrame, got err: %w", err)
		}
		fmt.Println("SettingsFrame decoded")

		return settingsFrame, nil
	default:
		// NOTE: in this case we have received unknown frames so discard it
		if _, err := io.CopyN(io.Discard, p.reader, int64(length)); err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("unknown frame Type: %d", frameType)
	}
}
