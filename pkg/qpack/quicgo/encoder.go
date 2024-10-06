package quicgo

import (
	"io"
	adapter "poghttp3/pkg/qpack"

	qpack "github.com/quic-go/qpack"
)

type quicgoQpackEncoder struct {
}

var _ adapter.QpackApi = (*quicgoQpackEncoder)(nil)

func NewQuicGoQpackEncoder() adapter.QpackApi {
	return &quicgoQpackEncoder{}
}

func (q *quicgoQpackEncoder) Encode(buffer io.Writer, headerFields ...adapter.HeaderField) error {
	encoder := qpack.NewEncoder(buffer)

	for _, headerField := range headerFields {
		if err := encoder.WriteField(qpack.HeaderField{
			Name:  headerField.Name,
			Value: headerField.Value,
		}); err != nil {
			// TODO: join errors
			continue
		}
	}

	return nil
}

func (q *quicgoQpackEncoder) Decode(reader io.Reader) ([]adapter.HeaderField, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	decoder := qpack.NewDecoder(nil)

	decodedFields, err := decoder.DecodeFull(data)
	if err != nil {
		return nil, err
	}

	var result []adapter.HeaderField
	for _, hf := range decodedFields {
		result = append(result, adapter.HeaderField{
			Name:  hf.Name,
			Value: hf.Value,
		})
	}

	return result, nil
}
