package http3

import (
	"bytes"
	qpack "poghttp3/pkg/qpack/quicgo"
	adapter "poghttp3/pkg/quic"
	"testing"
)

type MockUniStream struct {
	id adapter.StreamId
}

func (m *MockUniStream) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (m *MockUniStream) ID() adapter.StreamId {
	return m.id
}

type MockConn struct {
	id          string
	streamCount adapter.StreamId
}

func (m *MockConn) String() string {
	return m.id
}

func (m *MockConn) LocalAddress() string {
	return ""
}

func (m *MockConn) RemoteAddress() string {
	return ""
}

func (m *MockConn) Close(reason adapter.ApplicationError) {
}

func (m *MockConn) CreateUniStream(streamType adapter.StreamType) (adapter.QuicUniStream, error) {
	m.streamCount = m.streamCount + 1
	streamId := m.streamCount
	return &MockUniStream{
		id: streamId,
	}, nil
}

func TestControlStreamHandler(t *testing.T) {
	decoder := qpack.NewQuicGoQpackEncoder()
	server := NewServer("localhost:8080", decoder, nil)
	conn := &MockConn{}

	var testData = []struct {
		input []byte
		want  Settings
	}{
		{
			input: []byte{0x4, 0x2, 0x8, 0x1},
			want: Settings{
				ExtendedConnect: true,
			},
		},
	}

	for _, test := range testData {
		reader := bytes.NewReader(test.input)
		server.handleControlStream(conn, conn.streamCount, reader)
		conn.streamCount = conn.streamCount + 1
	}
}
