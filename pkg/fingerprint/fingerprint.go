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

func groupWords(s string, separator string, groupLength int) string {
	ss := strings.Split(s, separator)
	gs := "\t"
	j := 0
	for _, s := range ss {
		j++
		gs += s
		if j == groupLength {
			gs += "\n\t"
			j = 0
		} else {
			gs += " "
		}
	}

	return gs
}
