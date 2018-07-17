package gpg

import (
	"encoding/json"
	"fmt"
	"strings"
)

type KeyUsage uint8

type KeyUsages []KeyUsage

const (
	KeyUsageCertify KeyUsage = 1 << iota
	KeyUsageSign
	KeyUsageEncrypt
	KeyUsageAuthenticate
)

func (u *KeyUsage) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	switch strings.ToLower(s) {
	case "certify":
		*u = KeyUsageCertify
	case "sign":
		*u = KeyUsageSign
	case "encrypt":
		*u = KeyUsageEncrypt
	case "authenticate":
		*u = KeyUsageAuthenticate
	default:
		return fmt.Errorf("unknown usage type: %s", s)
	}

	return nil
}
