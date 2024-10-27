package http3

import (
	"io"
	frameparser "poghttp3/pkg/frameParser"
	adapter "poghttp3/pkg/quic"
)

func (s *Server) handleControlStream(conn adapter.QuicConn, id adapter.StreamId, reader io.Reader) {
	parser := frameparser.NewFrameParser(reader)
	frame, err := parser.ParseNextFrame()
	if err != nil {
		if s.logger != nil {
			s.logger.Debug("in control stream failed to read frame", "stream ID", id, "error", err)
		}
		conn.Close(SettingsError)
		return
	}

	settings, ok := frame.(*frameparser.SettingsFrame)
	if !ok {
		if s.logger != nil {
			s.logger.Debug("in control stream, first frame is not settings frame", "stream ID", id, "error", err)
		}
		conn.Close(MissingSettings)
	}

	for setting, value := range settings.Settings {
		switch setting {
		case frameparser.MaxFieldSectionSize:
			s.settings.MaxFieldSectionSize = value
		case frameparser.Datagrams:
			if value == 1 {
				s.settings.Datagrams = false // NOTE: allways refuse for now
			}
		case frameparser.ExtendedConnect:
			if value == 1 {
				s.settings.ExtendedConnect = true
			}
		}
	}
}
