package http3

import (
	"io"
	frameparser "poghttp3/pkg/frameParser"
	adapter "poghttp3/pkg/quic"
)

func (s *Server) handleControlStream(conn adapter.QuicConn, id adapter.StreamId, reader io.Reader) {
	parser := frameparser.NewFrameParser(reader)
	frame, err := parser.ParseNextFrame()

	httpConn, ok := s.connections[conn]
	if !ok {
		if s.logger != nil {
			s.logger.Debug(
				"failed to load http connection whist receiving control stream",
				"stream ID", id, "conn ID", conn.String(), "error", err,
			)
		}
		conn.Close(InternalError)
		return
	}

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
			httpConn.settings.MaxFieldSectionSize = value
		case frameparser.Datagrams:
			if value == 1 {
				httpConn.settings.Datagrams = false // NOTE: allways refuse for now
			}
		case frameparser.ExtendedConnect:
			if value == 1 {
				httpConn.settings.ExtendedConnect = true
			}
		}
	}
}
