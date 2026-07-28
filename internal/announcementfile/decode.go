package announcementfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

const MaxBytes int64 = 256 * 1024

func Decode(reader io.Reader) (protocol.AnnouncementDraft, error) {
	contents, err := io.ReadAll(io.LimitReader(reader, MaxBytes+1))
	if err != nil {
		return protocol.AnnouncementDraft{}, fmt.Errorf(
			"read announcement JSON: %w",
			err,
		)
	}
	if int64(len(contents)) > MaxBytes {
		return protocol.AnnouncementDraft{}, fmt.Errorf(
			"announcement JSON exceeds %d bytes",
			MaxBytes,
		)
	}
	if !utf8.Valid(contents) {
		return protocol.AnnouncementDraft{}, errors.New(
			"announcement JSON is not valid UTF-8",
		)
	}
	if err := validateUniqueJSON(contents); err != nil {
		return protocol.AnnouncementDraft{}, fmt.Errorf(
			"validate announcement JSON: %w",
			err,
		)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var draft protocol.AnnouncementDraft
	if err := decoder.Decode(&draft); err != nil {
		return protocol.AnnouncementDraft{}, fmt.Errorf(
			"decode announcement JSON: %w",
			err,
		)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return protocol.AnnouncementDraft{}, errors.New(
				"announcement file contains multiple JSON values",
			)
		}
		return protocol.AnnouncementDraft{}, fmt.Errorf(
			"decode announcement JSON: %w",
			err,
		)
	}
	return draft, nil
}

func validateUniqueJSON(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	if err := validateJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
