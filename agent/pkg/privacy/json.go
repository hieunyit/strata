package privacy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
)

// Body preserves duplicate keys, exact numbers and unchanged scalar spelling.
// It never guesses that an arbitrary plaintext body is a URL-encoded form.
func (f *Filter) Body(raw []byte) []byte {
	if len(raw) > MaxText || f != nil && f.strict && len(raw) > 0 {
		return []byte(Mask)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return raw
	}
	w := jsonFilter{filter: f, raw: raw, decoder: json.NewDecoder(bytes.NewReader(raw))}
	w.decoder.UseNumber()
	if err := w.value(false, 0); err == nil {
		if _, err := w.decoder.Token(); errors.Is(err, io.EOF) {
			return w.out.Bytes()
		}
	}
	trimmed := bytes.TrimSpace(raw)
	if trimmed[0] == '{' || trimmed[0] == '[' || trimmed[0] == '"' {
		return []byte(Mask)
	}
	return []byte(f.Text(string(raw)))
}

type jsonFilter struct {
	filter  *Filter
	raw     []byte
	decoder *json.Decoder
	out     bytes.Buffer
}

func (w *jsonFilter) token() (json.Token, []byte, error) {
	start := w.decoder.InputOffset()
	token, err := w.decoder.Token()
	if err != nil {
		return nil, nil, err
	}
	original := bytes.TrimLeft(w.raw[start:w.decoder.InputOffset()], " \t\r\n:,")
	return token, original, nil
}

func (w *jsonFilter) quoted(value string) { w.out.Write(strconv.AppendQuote(nil, value)) }

func (w *jsonFilter) value(sensitive bool, depth int) error {
	if depth > 32 {
		return errors.New("privacy: JSON depth exceeded")
	}
	token, original, err := w.token()
	if err != nil {
		return err
	}
	switch value := token.(type) {
	case json.Delim:
		if value != '{' && value != '[' {
			return errors.New("privacy: invalid JSON delimiter")
		}
		w.out.WriteByte(byte(value))
		first := true
		for w.decoder.More() {
			if !first {
				w.out.WriteByte(',')
			}
			first = false
			childSensitive := sensitive
			if value == '{' {
				keyToken, keyOriginal, err := w.token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("privacy: invalid JSON key")
				}
				masked := w.filter.Text(key)
				if masked != key {
					w.quoted(masked)
				} else {
					w.out.Write(keyOriginal)
				}
				w.out.WriteByte(':')
				childSensitive = childSensitive || w.filter.Sensitive(key)
			}
			if err := w.value(childSensitive, depth+1); err != nil {
				return err
			}
		}
		end, _, err := w.token()
		if err != nil {
			return err
		}
		want := json.Delim(']')
		if value == '{' {
			want = '}'
		}
		if end != want {
			return errors.New("privacy: invalid JSON end")
		}
		w.out.WriteByte(byte(want))
	case string:
		masked := w.filter.Text(value)
		if sensitive && !IsPseudonym(value) {
			masked = Mask
		}
		if masked != value {
			w.quoted(masked)
		} else {
			w.out.Write(original)
		}
	case json.Number:
		masked := w.filter.Text(value.String())
		if sensitive || masked != value.String() {
			w.quoted(Mask)
		} else {
			w.out.Write(original)
		}
	case bool, nil:
		if sensitive {
			w.quoted(Mask)
		} else {
			w.out.Write(original)
		}
	default:
		return errors.New("privacy: invalid JSON value")
	}
	if w.out.Len() > MaxText {
		return errors.New("privacy: JSON output exceeded limit")
	}
	return nil
}
