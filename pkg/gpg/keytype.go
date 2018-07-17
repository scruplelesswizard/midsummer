package gpg

import (
	"encoding/json"
	"errors"
	"strings"
)

type KeyType uint8

const (
	KeyTypeRSA KeyType = 1
)

func (t *KeyType) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	switch strings.ToUpper(s) {
	case "RSA":
		*t = KeyTypeRSA
	default:
		return errors.New("unknown algorithm type: " + s)
	}

	return nil
}
