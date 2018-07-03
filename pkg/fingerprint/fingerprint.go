package fingerprint

import (
	"crypto/sha256"
	"strings"

	"github.com/chaosaffe/pgpwordlist"
)

func Fingerprint(b []byte) (string, error) {

	hash := sha256.Sum256(b)

	s, err := pgpwordlist.ToString(hash[:])
	if err != nil {
		return "", err
	}

	return groupWords(s, " ", 4), nil
}

func groupWords(s, sep string, size int) string {
	result := "\t"
	for i, word := range strings.Split(s, sep) {
		result += word
		if i > 0 && i%size == 0 {
			result += "\n\t"
		} else {
			result += " "
		}
	}
	return result
}
