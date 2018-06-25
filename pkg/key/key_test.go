package key

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	yaml "gopkg.in/yaml.v2"
)

func TestKeyUnmarshal(t *testing.T) {

	k := PrimaryKey{}

	err := yaml.Unmarshal([]byte(testYAML), &k)
	if err != nil {
		t.Error(err)
	}

	if k.Usages[0] != KeyUsageCertify {
		t.Errorf("key usage not correct: expected %d, got %d", KeyUsageCertify, k.Usages[0])
		t.FailNow()
	}

	if k.Usages[1] != KeyUsageSign {
		t.Errorf("key usage not correct: expected %d, got %d", KeyUsageSign, k.Usages[1])
		t.FailNow()
	}

	spew.Dump(k)

}

const testYAML string = `
userIDs:
  - name: Test Case
    email: test@test.io
    comment: NOT A VALID KEY - DO NOT SIGN
    primary: true
  - name: Test Case 2
    email: nocomment@test.io
    primary: false
algorithm: RSA
length: 4096
usages:
  - certify
  - sign
expireDate: 90d
subkeys:
  - algorithm: RSA
    length: 4096
    usages:
      - encrypt
  - algorithm: RSA
    length: 4096
    usages:
      - authenticate`
