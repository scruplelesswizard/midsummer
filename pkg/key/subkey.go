package key

import (
	"golang.org/x/crypto/openpgp/packet"
)

type SubKey struct {
	Key
}

type SubKeys []*SubKey

func (sk *SubKey) GenerateSelfSig(keyid *uint64) (*packet.Signature, error) {
	return generateSelfSig(&sk.Key, keyid, packet.SigTypeSubkeyBinding)
}
