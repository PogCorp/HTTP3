package frameparser

import (
	"errors"
	"fmt"
	"io"
	"log"
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
func (p *FrameParser) ParseNextFrame() (Frame, error) {
	// read the frame type (the first byte)
	frameType, _, err := decodeVarint(p.reader)
	if err != nil {
		if errors.Is(err, io.EOF) {
			log.Println("End of File Received")
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read byte data, got err: %w", err)
	}

	length, err := p.readFrameLength()
	if err != nil {
		return nil, err
	}

	// parse frame according to it's type
	switch frameType {
	case FrameHeaders:
		headersFrame := &HeadersFrame{
			FrameLength: length,
		}
		if err := headersFrame.Decode(p.reader); err != nil {
			return nil, fmt.Errorf("failed to decode HeadersFrame, got err: %w", err)
		}

		return headersFrame, nil
	case FrameData:
		dataFrame := &DataFrame{
			FrameLength: length,
		}
		if err := dataFrame.Decode(p.reader); err != nil {
			return nil, fmt.Errorf("failed to decode DataFrame, got err: %w", err)
		}
		log.Printf("Decoded DataFrame: %s\n", dataFrame.Data)

		return dataFrame, nil
	case FrameSettings:
		settingsFrame := &SettingsFrame{
			FrameLength: length,
		}
		if err := settingsFrame.Decode(p.reader); err != nil {
			return nil, fmt.Errorf("failed to decode SettingsFrame, got err: %w", err)
		}
		log.Println("SettingsFrame decoded")

		return settingsFrame, nil
	case FrameGoAway:
		goawayFrame := &GoAwayFrame{
			FrameLength: length,
		}
		err = goawayFrame.Decode(p.reader)
		if err != nil {
			return nil, err
		}
		return goawayFrame, nil
	default:
		reservedFrame := &ReservedFrame{
			FrameId:     frameType,
			FrameLength: length,
		}
		if err := reservedFrame.Decode(p.reader); err != nil {
			log.Printf("failed to decode ReservedFrame, got err: %s", err)
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
