package key

import (
	"crypto/rsa"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

type PrimaryKey struct {
	Key
	UserIds *UserIds `json:"userids"`
	SubKeys *SubKeys `json:"subkeys"`
}

func (pk *PrimaryKey) GenerateSelfSig(keyid *uint64) *packet.Signature {

	return generateSelfSig(&pk.Key, keyid, packet.SigTypePositiveCert)

}

func (pk *PrimaryKey) generateSubKeys(gt time.Time, e *openpgp.Entity) ([]openpgp.Subkey, error) {

	sks := []openpgp.Subkey{}

	for _, sk := range *pk.SubKeys {

		nKey, err := rsa.GenerateKey(pk.Config.Random(), sk.Length)
		if err != nil {
			return nil, err
		}

		sks = append(sks, openpgp.Subkey{
			PublicKey:  packet.NewRSAPublicKey(gt, &nKey.PublicKey),
			PrivateKey: packet.NewRSAPrivateKey(gt, nKey),
			Sig:        sk.GenerateSelfSig(&e.PrimaryKey.KeyId),
		},
		)

		for _, sk := range sks {
			sk.PublicKey.IsSubkey = true
			sk.PrivateKey.IsSubkey = true
		}

	}

	return sks, nil

}
