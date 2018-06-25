package main

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"log"
	"math"
	"strings"

	"github.com/chaosaffe/midsummer/pkg/key"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func main() {

	k := key.PrimaryKey{
		UIDs: &key.UIDs{
			&key.UID{
				Name:  "Test",
				Email: "test@not.valid",
			},
		},
		Key: key.Key{
			Length: 4096,
			Type:   "RSA",
			Usage:  []string{"certify", "sign"},
			Config: packet.Config{},
		},
	}

	gt := k.Config.Now()

	config := k.Config

	uid := (*k.UIDs)[0].ToPacket()
	if uid == nil {
		return
	}

	primaryKey, err := rsa.GenerateKey(config.Random(), k.Length)
	if err != nil {
		return
	}

	e := &openpgp.Entity{
		PrimaryKey: packet.NewRSAPublicKey(gt, &primaryKey.PublicKey),
		PrivateKey: packet.NewRSAPrivateKey(gt, primaryKey),
		Identities: make(map[string]*openpgp.Identity),
	}

	e.Identities[uid.Id] = &openpgp.Identity{
		Name:          uid.Name,
		UserId:        uid,
		SelfSignature: k.GenerateSelfSig(gt, &e.PrimaryKey.KeyId),
	}

	e.Subkeys, err = k.GenerateSubKeys(gt, e)
	if err != nil {
		return
	}

	signingKey := packet.NewRSAPrivateKey(gt, primaryKey)

	for _, id := range e.Identities {
		err := id.SelfSignature.SignUserId(uid.Id, e.PrimaryKey, signingKey, nil)
		if err != nil {
			fmt.Println(err)
			return
		}
	}

	// Sign subkeys
	for _, subkey := range e.Subkeys {
		err := subkey.Sig.SignKey(subkey.PublicKey, signingKey, nil)
		if err != nil {
			log.Fatal(err)
		}
	}
	//
	// yaml, _ := yaml.Marshal(e)
	// fmt.Println(string(yaml))

	buffer := &bytes.Buffer{}

	w, err := armor.Encode(buffer, openpgp.PublicKeyType, map[string]string{})

	e.Serialize(w)
	w.Close()

	// fp := e.PrimaryKey.Fingerprint[:]
	//
	// hex := hex.EncodeToString(fp)
	//
	// fmt.Println(hex)
	//
	// wl, err := pgpwordlist.ToString(fp)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	//
	// splitList := strings.Split(wl, " ")
	//
	// fmt.Println(groupLine(splitList, 4))
	//
	// fmt.Println(buffer.String())
	r, err := armor.Decode(strings.NewReader(buffer.String()))
	fromReader := packet.NewReader(r.Body)
	_, err = openpgp.ReadEntity(fromReader)
	if err != nil {
		log.Fatal(err)
	}
}

func groupLine(s []string, groupLen int) string {
	l := len(s)
	ss := "\t"
	for i := 0; i < l; i++ {
		ss += s[i] + " "
		m := math.Mod(float64(i), float64(groupLen))
		if m == float64(groupLen-1) {
			ss += "\n\t"
		}
	}
	return ss
}
