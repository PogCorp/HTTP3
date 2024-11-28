package http3

import (
	"bytes"
	adapter "poghttp3/pkg/quic"
	"reflect"
	"testing"

	qpack "github.com/PogCorp/HTTP3/pkg/qpack/quicgo"
)

type MockUniStream struct {
	id      adapter.StreamId
	written bytes.Buffer
}

func (m *MockUniStream) Write(p []byte) (n int, err error) {
	return m.written.Write(p)
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
	factory := &qpack.QuicGoQpackFactory{}
	server := NewServer("localhost:8080", factory, nil)
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

	for i, test := range testData {
		// precondition of handleControlStream is that connection has been stabilshed and
		// this connection has been registered in the server
		httpConn := &connection{}
		server.connections[conn] = httpConn
		reader := bytes.NewReader(test.input)
		server.handleControlStream(conn, conn.streamCount, reader)
		if equal := reflect.DeepEqual(httpConn.settings, test.want); !equal {
			t.Fatalf("expected received settings %+v, got %+v", test.want, httpConn.settings)
		}
		conn.streamCount = adapter.StreamId(i + 1)
	}
}

func TestReadUnidirectionalControlStream(t *testing.T) {
	factory := &qpack.QuicGoQpackFactory{}
	server := NewServer("localhost:8080", factory, nil)
	conn := &MockConn{}
	var testData = []struct {
		input []byte
		want  Settings
	}{
		{
			input: []byte{0x0, 0x4, 0x2, 0x8, 0x1},
			want: Settings{
				ExtendedConnect: true,
			},
		},
	}

	for _, test := range testData {
		reader := bytes.NewReader(test.input)
		server.OnNewConnection(conn)
		if len(server.connections) < 1 {
			t.Fatal("expected server.connections to be equal to 1")
		}
		server.OnReadUniStream(conn, conn.streamCount, reader)
		conn.streamCount = conn.streamCount + 1
	}
}
