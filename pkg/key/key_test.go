package key

import (
	"testing"

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

	if len(*k.SubKeys) != 2 {
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

const testYAML string = `
userids:
  - name: Test Case
    email: test@test.io
    comment: NOT A VALID KEY - DO NOT SIGN
    primary: true
  - name: Test Case 2
    email: nocomment@test.io
    primary: false
type: RSA
length: 4096
usages:
  - certify
  - sign
expirydate: 30m
subkeys:
  - algorithm: RSA
    length: 4096
    usages:
      - encrypt
  - algorithm: RSA
    length: 4096
    usages:
      - authenticate`

// const testYAML string = `
// userids:
//   - name: Test Case
//     email: test@test.io
//     comment: NOT A VALID KEY - DO NOT SIGN
//     primary: true
//   - name: Test Case 2
//     email: nocomment@test.io
//     primary: false
// type: RSA
// length: 4096
// usages:
//   - certify
//   - sign
// expirydate: 2014-05-16T08:28:06.801064-04:00
// subkeys:
//   - algorithm: RSA
//     length: 4096
//     usages:
//       - encrypt
//   - algorithm: RSA
//     length: 4096
//     usages:
//       - authenticate`
