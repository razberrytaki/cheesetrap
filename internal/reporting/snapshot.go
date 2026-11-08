package reporting

import (
	"bytes"
	"encoding/json"
	"io"

	"cheesetrap/internal/domain"
)

type snapshotJSONField struct {
	key    string
	prefix []byte
	value  json.RawMessage
}

// Marshal the small scaffold through the real domain type so added fields and
// omission rules remain automatic. Only the two large arrays are streamed.
func snapshotJSONFields(snapshot domain.ReportSnapshot) ([]snapshotJSONField, error) {
	snapshot.Evidence, snapshot.Rules = nil, nil
	data, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if token != json.Delim('{') {
		return nil, ErrRevisionInput
	}
	var fields []snapshotJSONField
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, ErrRevisionInput
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		prefix, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		fields = append(fields, snapshotJSONField{key: key, prefix: append(prefix, ':'), value: value})
	}
	token, err = decoder.Token()
	if err != nil {
		return nil, err
	}
	if token != json.Delim('}') {
		return nil, ErrRevisionInput
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, ErrRevisionInput
	}
	return fields, nil
}

// Count and validate before allocating the final buffer. Both passes marshal
// one array element at a time, so neither retains a second whole-snapshot
// encoding buffer. Domain marshaling preserves the exact former JSON bytes.
func marshalReportSnapshot(snapshot domain.ReportSnapshot) ([]byte, error) {
	fields, err := snapshotJSONFields(snapshot)
	if err != nil {
		return nil, err
	}
	var size snapshotJSONSize
	if err := writeSnapshotJSON(&size, fields, snapshot); err != nil {
		return nil, err
	}
	output := snapshotJSONOutput{data: make([]byte, size.n)}
	if err := writeSnapshotJSON(&output, fields, snapshot); err != nil {
		return nil, err
	}
	if output.n != len(output.data) {
		return nil, io.ErrShortWrite
	}
	return output.data, nil
}

func writeSnapshotJSON(w io.Writer, fields []snapshotJSONField, snapshot domain.ReportSnapshot) error {
	if err := writeSnapshotBytes(w, []byte{'{'}); err != nil {
		return err
	}
	for i, field := range fields {
		if i > 0 {
			if err := writeSnapshotBytes(w, []byte{','}); err != nil {
				return err
			}
		}
		if err := writeSnapshotBytes(w, field.prefix); err != nil {
			return err
		}
		var err error
		switch field.key {
		case "evidence":
			err = writeSnapshotArray(w, snapshot.Evidence)
		case "rules":
			err = writeSnapshotArray(w, snapshot.Rules)
		default:
			err = writeSnapshotBytes(w, field.value)
		}
		if err != nil {
			return err
		}
	}
	return writeSnapshotBytes(w, []byte{'}'})
}

func writeSnapshotArray[T any](w io.Writer, values []T) error {
	if values == nil {
		return writeSnapshotBytes(w, []byte("null"))
	}
	if err := writeSnapshotBytes(w, []byte{'['}); err != nil {
		return err
	}
	for i, value := range values {
		if i > 0 {
			if err := writeSnapshotBytes(w, []byte{','}); err != nil {
				return err
			}
		}
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if err := writeSnapshotBytes(w, data); err != nil {
			return err
		}
	}
	return writeSnapshotBytes(w, []byte{']'})
}

func writeSnapshotBytes(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

type snapshotJSONSize struct{ n int }

func (w *snapshotJSONSize) Write(data []byte) (int, error) {
	if len(data) > int(^uint(0)>>1)-w.n {
		return 0, ErrRevisionInput
	}
	w.n += len(data)
	return len(data), nil
}

type snapshotJSONOutput struct {
	data []byte
	n    int
}

func (w *snapshotJSONOutput) Write(data []byte) (int, error) {
	if len(data) > len(w.data)-w.n {
		return 0, io.ErrShortWrite
	}
	copy(w.data[w.n:], data)
	w.n += len(data)
	return len(data), nil
}
