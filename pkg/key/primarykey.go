package key

import (
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

type PrimaryKey struct {
	Key
	UserIds *UserIds `json:"userids"`
	SubKeys *SubKeys `json:"subkeys"`
}

func (pk *PrimaryKey) Generate() (*openpgp.Entity, error) {
	rsaKey, err := pk.generateKey()
	if err != nil {
		return nil, err
	}

	primKey := packet.NewRSAPublicKey(pk.Config.Now(), &rsaKey.PublicKey)
	privKey := packet.NewRSAPrivateKey(pk.Config.Now(), rsaKey)

	e := &openpgp.Entity{
		PrimaryKey: primKey,
		PrivateKey: privKey,
	}

	pk.setEntityUIDs(e)

	for _, id := range e.Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, e.PrimaryKey, e.PrivateKey, nil)
		if err != nil {
			return nil, err
		}
	}

	e.Subkeys, err = pk.generateSubKeys(pk.Config.Now(), e)
	if err != nil {
		return nil, err
	}

	// Sign subkeys
	for _, subkey := range e.Subkeys {
		err := subkey.Sig.SignKey(subkey.PublicKey, e.PrivateKey, nil)
		if err != nil {
			return nil, err
		}
	}
	return e, nil
}

func (pk *PrimaryKey) setEntityUIDs(e *openpgp.Entity) error {

	e.Identities = make(map[string]*openpgp.Identity)

	for _, uid := range pk.UserIds.ToPacket() {
		e.Identities[uid.Id] = &openpgp.Identity{
			Name:   uid.Name,
			UserId: uid,
		}
		sig, err := pk.generateSelfSig(&e.PrimaryKey.KeyId)
		if err != nil {
			return err
		}
		e.Identities[uid.Id].SelfSignature = sig
	}
	return nil
}

func (pk *PrimaryKey) generateSelfSig(keyid *uint64) (*packet.Signature, error) {
	return generateSelfSig(&pk.Key, keyid, packet.SigTypePositiveCert)
}

func (pk *PrimaryKey) generateSubKeys(gt time.Time, e *openpgp.Entity) ([]openpgp.Subkey, error) {

	sks := []openpgp.Subkey{}

	for _, sk := range *pk.SubKeys {

		rsaKey, err := sk.generateKey()
		if err != nil {
			return nil, err
		}

		sig, err := sk.GenerateSelfSig(&e.PrimaryKey.KeyId)
		if err != nil {
			return nil, err
		}

		sks = append(sks, openpgp.Subkey{
			PublicKey:  packet.NewRSAPublicKey(gt, &rsaKey.PublicKey),
			PrivateKey: packet.NewRSAPrivateKey(gt, rsaKey),
			Sig:        sig,
		},
		)

		for _, sk := range sks {
			sk.PublicKey.IsSubkey = true
			sk.PrivateKey.IsSubkey = true
		}

	}
	return sks, nil
}
