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
	splitStrings := strings.Split(s, separator)
	groupedStrings := "\t"
	i := 0
	for _, s := range splitStrings {
		i++
		groupedStrings += s
		if i == groupLength {
			groupedStrings += "\n\t"
			i = 0
		} else {
			groupedStrings += " "
		}
	}
	return groupedStrings
}
