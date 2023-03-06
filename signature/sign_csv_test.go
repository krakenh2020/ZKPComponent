package signature

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/stretchr/testify/assert"
)

func TestSignCsv(t *testing.T) {
	signature.Register(signature.EDDSA_BN254, eddsa.GenerateKeyInterfaces)
	signer, err := signature.EDDSA_BN254.New(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := signer.Public()

	sign, err := SignCsv("../datasets/framingham_tiny.csv", signer)
	if err != nil {
		t.Fatal(err)
	}

	err = WriteSignCsv("../datasets/framingham_tiny.csv", "../datasets/framingham_tiny_signed.csv", sign)
	if err != nil {
		t.Fatal(err)
	}

	check, err := VerifyCsv("../datasets/framingham_tiny_signed.csv", pubKey)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, check)

}
