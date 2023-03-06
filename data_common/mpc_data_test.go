package data_common

import (
	"math/big"
	"testing"

	"github.com/krakenh2020/ZKPComponent/key_management"
	"github.com/stretchr/testify/assert"
)

func TestSharesShamir(t *testing.T) {
	n := 100
	a, err := NewUniformRandomVector(n, MPCPrimeHalf)
	assert.NoError(t, err)

	shares, err := CreateSharesShamir(a)
	assert.NoError(t, err)

	b, err := JoinSharesShamir(shares)
	assert.NoError(t, err)

	assert.Equal(t, a, b)
}

func TestCsvFileSplitJoin(t *testing.T) {
	pubKey, err := key_management.LoadPubKey("test", "../key_management/keys")
	assert.NoError(t, err)
	secKey, err := key_management.LoadSecKey("test", "../key_management/keys")
	assert.NoError(t, err)

	pubKeys := [][]byte{pubKey, pubKey, pubKey}
	vec, _, _, err := SplitCsvFile("../datasets/framingham_tiny.csv", "../datasets/framingham_tiny_enc.txt", pubKeys)
	assert.NoError(t, err)

	shares := make([][]*big.Int, 3)
	for i := 0; i < 3; i++ {
		shares[i], _, err = ReadShare("../datasets/framingham_tiny_enc.txt", pubKey, secKey, i)
		assert.NoError(t, err)
	}

	b := JoinSharesShamirFloat(shares)
	for i, _ := range vec {
		assert.LessOrEqual(t, vec[i], b[i]+0.1)
		assert.GreaterOrEqual(t, vec[i]+0.1, b[i])
	}
}
