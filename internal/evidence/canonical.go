package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// CanonicalJSON sorts object keys, rejects duplicates/trailing values and
// preserves exact decimal values. Array order, null, booleans and strings stay
// significant. Numbers use normalized scientific notation (1 and 1.0 match).
// This is Sifruno evidence canonicalization v1, not RFC 8785/JCS.
func CanonicalJSON(data []byte) ([]byte, error) {
	if len(data) > MaxBundleBytes || !utf8.Valid(data) {
		return nil, errors.New("JSON exceeds bounds or is not UTF-8")
	}
	if err := validUnicodeEscapes(data); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	nodes := 0
	v, err := readValue(d, 0, &nodes)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON value or syntax")
	}
	return json.Marshal(v)
}

// encoding/json replaces isolated UTF-16 surrogates with U+FFFD. Reject them
// instead, so two malformed strings cannot compare equal through replacement.
func validUnicodeEscapes(data []byte) error {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		if i+1 >= len(data) {
			return errors.New("incomplete JSON string escape")
		}
		if data[i+1] != 'u' {
			i++
			continue
		}
		if i+5 >= len(data) {
			return errors.New("incomplete JSON Unicode escape")
		}
		value, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
		if err != nil {
			return errors.New("invalid JSON Unicode escape")
		}
		if value >= 0xd800 && value <= 0xdbff {
			if i+11 >= len(data) || data[i+6] != '\\' || data[i+7] != 'u' {
				return errors.New("unpaired high JSON surrogate")
			}
			low, err := strconv.ParseUint(string(data[i+8:i+12]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return errors.New("invalid JSON surrogate pair")
			}
			i += 11
		} else if value >= 0xdc00 && value <= 0xdfff {
			return errors.New("unpaired low JSON surrogate")
		} else {
			i += 5
		}
	}
	return nil
}

func readValue(d *json.Decoder, depth int, nodes *int) (any, error) {
	*nodes++
	if depth > 64 || *nodes > 100000 {
		return nil, errors.New("JSON nesting or node limit exceeded")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '{':
			m := map[string]any{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return nil, err
				}
				key, ok := k.(string)
				if !ok {
					return nil, errors.New("non-string object key")
				}
				if _, exists := m[key]; exists {
					return nil, fmt.Errorf("duplicate JSON object key %q", key)
				}
				value, err := readValue(d, depth+1, nodes)
				if err != nil {
					return nil, err
				}
				m[key] = value
			}
			close, err := d.Token()
			if err != nil || close != json.Delim('}') {
				return nil, errors.New("invalid JSON object")
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				value, err := readValue(d, depth+1, nodes)
				if err != nil {
					return nil, err
				}
				a = append(a, value)
			}
			close, err := d.Token()
			if err != nil || close != json.Delim(']') {
				return nil, errors.New("invalid JSON array")
			}
			return a, nil
		default:
			return nil, errors.New("unexpected JSON delimiter")
		}
	case json.Number:
		return normalizeNumber(string(v))
	case string, bool, nil:
		return v, nil
	default:
		return nil, errors.New("unsupported JSON token")
	}
}

func normalizeNumber(s string) (json.Number, error) {
	if len(s) > 1024 {
		return "", errors.New("JSON number exceeds 1024 characters")
	}
	negative := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	exponent := 0
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		var err error
		exponent, err = strconv.Atoi(s[i+1:])
		if err != nil || exponent < -512 || exponent > 512 {
			return "", errors.New("JSON exponent exceeds bounds")
		}
		s = s[:i]
	}
	if i := strings.IndexByte(s, '.'); i >= 0 {
		exponent -= len(s) - i - 1
		s = s[:i] + s[i+1:]
	}
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return json.Number("0"), nil
	}
	for strings.HasSuffix(s, "0") {
		s = s[:len(s)-1]
		exponent++
	}
	exponent += len(s) - 1
	if len(s) > 1 {
		s = s[:1] + "." + s[1:]
	}
	if negative {
		s = "-" + s
	}
	return json.Number(s + "e" + strconv.Itoa(exponent)), nil
}
