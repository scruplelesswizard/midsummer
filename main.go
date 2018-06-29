package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/chaosaffe/midsummer/pkg/fingerprint"
	"github.com/chaosaffe/midsummer/pkg/key"
	"github.com/ghodss/yaml"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

const (
	InputYes = "y\n"
	InputNo  = "n\n"
)

func main() {

	// read in file
	data, err := ioutil.ReadFile("example.yaml")
	if err != nil {
		panic(err)
	}

	// fingerprint and confirm file
	fpr, err := fingerprint.Fingerprint(data)
	reader := bufio.NewReader(os.Stdin)
	var in string
	for {
		fmt.Printf("\nInput File Fingerprint:\n\n%s\nIs the fingerprint correct?: (y/n) ", fpr)
		in, err = reader.ReadString('\n')
		if err != nil {
			panic(err)
		}
		if validInput(in) {
			break
		}
	}

	if strings.ToLower(in) == InputNo {
		fmt.Println("Input does not match. Exiting...")
		os.Exit(1)
	}
	// TODO: foreach key

	keys := key.Keys{}

	err = yaml.Unmarshal(data, &keys)
	if err != nil {
		panic(err)
	}

	for _, k := range keys {

		prim := k.UserIds.Primary()
		if prim == nil {
			panic("No primary user ID set")
		}

		fmt.Printf("Generating %s\n", prim.Name)

		e, err := k.Generate()
		if err != nil {
			panic(err)
		}

		writePublicFile(e)
		writePrivateFile(e, k)

	}

}

func validInput(s string) bool {
	s = strings.ToLower(s)
	valid := s == InputYes || s == InputNo
	if !valid {
		fmt.Printf("\n\nInvalid input. Please try again.\n\n")
	}
	return valid
}

func writePrivateFile(e *openpgp.Entity, k key.PrimaryKey) {
	f, err := os.Create(fmt.Sprintf("private-%s.sec", e.PrimaryKey.KeyIdString()))
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w, err := armor.Encode(f, openpgp.PrivateKeyType, map[string]string{})
	if err != nil {
		panic(err)
	}
	defer w.Close()

	e.SerializePrivate(w, &k.Config)
}

func writePublicFile(e *openpgp.Entity) {
	f, err := os.Create(fmt.Sprintf("public-%s.asc", e.PrimaryKey.KeyIdString()))
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w, err := armor.Encode(f, openpgp.PublicKeyType, map[string]string{})
	if err != nil {
		panic(err)
	}
	defer w.Close()

	e.Serialize(w)
}

// 	hashed subpkt 33 len 21 (issuer fpr v4 CC6502CE76FDE7C08F3AFAFFE4B72F09BF26747D)
// 	hashed subpkt 30 len 1 (features: 01)
// 	hashed subpkt 23 len 1 (keyserver preferences: 80)
