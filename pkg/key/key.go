package key

import (
	"crypto/rsa"
	"fmt"
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
	d := time.Time(k.ExpiryDate).Sub(gt)
	sec := uint32(d.Seconds())
	return &sec
}

func generateSelfSig(k *Key, keyid *uint64, sigType packet.SignatureType) (*packet.Signature, error) {
	sig := &packet.Signature{
		CreationTime:         k.Config.Now(),
		SigType:              sigType,
		PubKeyAlgo:           packet.PubKeyAlgoRSA,
		Hash:                 k.Config.Hash(),
		IssuerKeyId:          keyid,
		KeyLifetimeSecs:      k.LifetimeSeconds(k.Config.Now()),
		PreferredSymmetric:   k.PreferredSymmetric,
		PreferredHash:        k.PreferredHash,
		PreferredCompression: k.PreferredCompression,
	}

	err := k.setSignatureFlags(sig)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (k *Key) generateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(k.Config.Random(), k.Length)
}

func (k *Key) setSignatureFlags(sig *packet.Signature) error {

	sig.FlagsValid = true

	for _, u := range k.Usages {
		switch u {
		case KeyUsageSign:
			sig.FlagSign = true
		case KeyUsageCertify:
			sig.FlagCertify = true
		case KeyUsageEncrypt:
			sig.FlagEncryptStorage = true
			sig.FlagEncryptCommunications = true
		case KeyUsageAuthenticate:
			sig.FlagAuthenticate = true
		default:
			return fmt.Errorf("unknown key usage type")
		}
	}
	return nil
}
