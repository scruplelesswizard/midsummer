package gpg

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type dateOrDuration time.Time

func (dd *dateOrDuration) UnmarshalJSON(b []byte) error {
	var s string

	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	exp, err := time.Parse(time.RFC3339, s)
	if err != nil {
		d, derr := tryDurationParse(s)
		if derr != nil {
			return err
		}
		exp = time.Now().Add(d)
	}
	*dd = dateOrDuration(exp)

	return nil
}

func tryDurationParse(s string) (time.Duration, error) {
	d, err := parseBigSuffix(s)
	if err != nil {
		return d, fmt.Errorf("invalid duration: %s", err.Error())
	}
	return d, nil
}

// duation consts
const (
	day   = time.Hour * 24
	month = day * 30
	year  = day * 365
)

//duration suffix consts
const (
	daySuffix   = "d"
	monthSuffix = "M"
	yearSuffix  = "y"
)

func parseBigSuffix(s string) (time.Duration, error) {
	var (
		d   time.Duration
		err error
	)
	switch {
	case strings.HasSuffix(s, daySuffix):
		s = strings.TrimSuffix(s, daySuffix)
		d, err = buildDuration(s, day)
	case strings.HasSuffix(s, monthSuffix):
		s = strings.TrimSuffix(s, monthSuffix)
		d, err = buildDuration(s, month)
	case strings.HasSuffix(s, yearSuffix):
		s = strings.TrimSuffix(s, yearSuffix)
		d, err = buildDuration(s, year)
	default:
		return time.ParseDuration(s)
	}
	if err != nil {
		return d, err
	}

	return d, nil
}

func buildDuration(s string, d time.Duration) (time.Duration, error) {

	multiplicand, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}

	return time.Duration(multiplicand) * d, nil

}
