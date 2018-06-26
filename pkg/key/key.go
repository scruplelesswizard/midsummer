package key

import (
	"time"

	"golang.org/x/crypto/openpgp/packet"
)

type Key struct {
	Length                                                  int
	Type                                                    KeyType
	Usages                                                  KeyUsages
	ExpiryDate                                              dateOrDuration
	Config                                                  packet.Config
	PreferredSymmetric, PreferredHash, PreferredCompression []uint8
}

func (k *Key) LifetimeSeconds(gt time.Time) *uint32 {
	d := gt.Sub(time.Time(k.ExpiryDate))
	sec := uint32(d.Seconds())
	return &sec
}

func generateSelfSig(k *Key, keyid *uint64, sigType packet.SignatureType) *packet.Signature {
	return &packet.Signature{
		CreationTime:              k.Config.Now(),
		SigType:                   sigType,
		PubKeyAlgo:                packet.PubKeyAlgoRSA,
		Hash:                      k.Config.Hash(),
		FlagsValid:                true,
		FlagEncryptStorage:        true,
		FlagEncryptCommunications: true,
		IssuerKeyId:               keyid,
		KeyLifetimeSecs:           k.LifetimeSeconds(k.Config.Now()),
		PreferredSymmetric:        k.PreferredSymmetric,
		PreferredHash:             k.PreferredHash,
		PreferredCompression:      k.PreferredCompression,
	}
}
