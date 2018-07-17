package gpg

import (
	"testing"
	"time"

	"github.com/ghodss/yaml"
)

func TestKeyUnmarshal(t *testing.T) {

	k := PrimaryKey{}

	err := yaml.Unmarshal([]byte(testYAML), &k)
	if err != nil {
		t.Error(err)
	}

	if len(k.Usages) != 2 {
		t.Errorf("key usages not parsed")
		t.FailNow()
	}

	if len(*k.SubKeys) != 4 {
		t.Errorf("subkeys not parsed")
		t.FailNow()
	}

	if len(*k.UserIds) != 2 {
		t.Errorf("userids not parsed")
		t.FailNow()
	}

	if k.Usages[0] != KeyUsageCertify {
		t.Errorf("key usage not correct: expected %d, got %d", KeyUsageCertify, k.Usages[0])
		t.FailNow()
	}

	if k.Usages[1] != KeyUsageSign {
		t.Errorf("key usage not correct: expected %d, got %d", KeyUsageSign, k.Usages[1])
		t.FailNow()
	}

}

func TestGenerate(t *testing.T) {

	k := PrimaryKey{}

	err := yaml.Unmarshal([]byte(testYAML), &k)
	if err != nil {
		t.Error(err)
	}

	_, err = k.Generate()
	if err != nil {
		t.Error(err)
	}

}

func TestLifetimeSeconds(t *testing.T) {
	tt, err := time.Parse(time.RFC3339, "2018-12-31T00:00:00-00:00")
	if err != nil {
		panic(err)
	}

	gt := time.Now().UTC()

	k := Key{
		ExpiryDate: dateOrDuration(tt),
	}

	sec := k.LifetimeSeconds(gt)

	timeDiff := time.Second * time.Duration(*sec)

	ft := gt.Add(timeDiff)

	if !tt.Round(time.Minute).Equal(ft.Round(time.Minute)) {
		t.Errorf("time difference not correct: expected %s, got %s", tt.Format(time.RFC3339), ft.Format(time.RFC3339))
		t.Fail()
	}

}

const testYAML string = `
type: RSA
length: 4096
usages:
  - certify
  - sign
expires_after: 1M
userids:
  - name: Test Case
    email: test@test.io
    comment: NOT A VALID KEY - DO NOT SIGN
    primary: true
  - name: Test Case 2
    email: nocomment@test.io
    primary: false
subkeys:
  - type: RSA
    length: 4096
    usages:
      - encrypt
    expires_after: 1d
  - type: RSA
    length: 4096
    usages:
      - authenticate
    expires_after: 1y
  - type: RSA
    length: 4096
    usages:
      - sign
      - certify
    expires_after: 2018-12-31T15:59:59-08:00
  - type: RSA
    length: 4096
    usages:
      - sign
      - certify
    expires_after: 12h
perferred_symmetric:
  - 9
  - 8
  - 7
  - 2
perferred_hash:
  - 10
  - 9
  - 8
  - 11
  - 2
perferred_compression:
  - 2
  - 3
  - 1
`
