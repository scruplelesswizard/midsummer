package key

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/ghodss/yaml"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

type KeyUsage uint8

type KeyUsages []KeyUsage

const (
	KeyUsageCertify KeyUsage = 1 << iota
	KeyUsageSign
	KeyUsageEncrypt
	KeyUsageAuthenticate
)

type KeyType uint8

const (
	KeyTypeRSA KeyType = 1
)

type SubKeys []*SubKey

type Key struct {
	Length                                                  int
	Type                                                    KeyType
	Usages                                                  KeyUsages
	ExpiryDate                                              time.Time
	Config                                                  packet.Config
	PreferredSymmetric, PreferredHash, PreferredCompression []uint8
}

type SubKey struct {
	Key `yaml:",inline"`
}

type PrimaryKey struct {
	Key     `yaml:",inline"`
	UserIds *UserIds `yaml:"userIDs"`
	SubKeys SubKeys  `yaml:"subkeys"`
}

func (k *Key) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var ak struct {
		Length                                                  int
		Type                                                    KeyType
		Usages                                                  KeyUsages
		ExpiryDate                                              dateOrDuration
		Config                                                  packet.Config
		PreferredSymmetric, PreferredHash, PreferredCompression []uint8
		UserIds                                                 *UserIds
		SubKeys                                                 SubKeys
	}
	err := unmarshal(&ak)
	if err != nil {
		return err
	}

	spew.Dump(ak)

	k.Length = ak.Length
	k.Type = ak.Type
	k.Usages = ak.Usages
	k.ExpiryDate = time.Time(ak.ExpiryDate)
	k.Config = ak.Config
	k.PreferredSymmetric = ak.PreferredSymmetric
	k.PreferredHash = ak.PreferredHash
	k.PreferredCompression = ak.PreferredCompression

	return nil
}

func (u *KeyUsage) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	switch strings.ToLower(s) {
	case "certify":
		*u = KeyUsageCertify
	case "sign":
		*u = KeyUsageSign
	case "encrypt":
		*u = KeyUsageEncrypt
	case "authenticate":
		*u = KeyUsageAuthenticate
	default:
		return errors.New("unknown usage type: " + s)
	}

	return nil
}

func (a *KeyType) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	switch strings.ToUpper(s) {
	case "RSA":
		*a = KeyTypeRSA
	default:
		return errors.New("unknown algorithm type: " + s)
	}

	return nil
}

func unmarshalKeyUsage(b []byte) error {
	fmt.Println("blah")
	var s string
	yaml.Unmarshal(b, s)
	fmt.Println(s)

	return nil
}

func (k *Key) LifetimeSeconds(gt time.Time) *uint32 {
	d := gt.Sub(k.ExpiryDate)
	sec := uint32(d.Seconds())
	return &sec
}

func (pk *PrimaryKey) GenerateSelfSig(gt time.Time, i *uint64) *packet.Signature {

	return generateSelfSig(&pk.Key, gt, i, packet.SigTypePositiveCert)

}

func (sk *SubKey) GenerateSelfSig(gt time.Time, i *uint64) *packet.Signature {

	return generateSelfSig(&sk.Key, gt, i, packet.SigTypeSubkeyBinding)

}

func generateSelfSig(k *Key, gt time.Time, i *uint64, sigType packet.SignatureType) *packet.Signature {
	return &packet.Signature{
		CreationTime:              gt,
		SigType:                   sigType,
		PubKeyAlgo:                packet.PubKeyAlgoRSA,
		Hash:                      k.Config.Hash(),
		FlagsValid:                true,
		FlagEncryptStorage:        true,
		FlagEncryptCommunications: true,
		IssuerKeyId:               i,
		KeyLifetimeSecs:           k.LifetimeSeconds(gt),
		PreferredSymmetric:        k.PreferredSymmetric,
		PreferredHash:             k.PreferredHash,
		PreferredCompression:      k.PreferredCompression,
	}
}

func (pk *PrimaryKey) GenerateSubKeys(gt time.Time, e *openpgp.Entity) ([]openpgp.Subkey, error) {

	sks := []openpgp.Subkey{}

	for _, sk := range pk.SubKeys {

		nKey, err := rsa.GenerateKey(pk.Config.Random(), sk.Length)
		if err != nil {
			return nil, err
		}

		sks = append(sks, openpgp.Subkey{
			PublicKey:  packet.NewRSAPublicKey(gt, &nKey.PublicKey),
			PrivateKey: packet.NewRSAPrivateKey(gt, nKey),
			Sig:        sk.GenerateSelfSig(gt, &e.PrimaryKey.KeyId),
		},
		)

		for _, sk := range sks {
			sk.PublicKey.IsSubkey = true
			sk.PrivateKey.IsSubkey = true
		}

	}

	return sks, nil

}
