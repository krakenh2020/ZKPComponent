package encryption_test

import (
	"github.com/krakenh2020/ZKPcomponent/encryption"
	"testing"

	"github.com/krakenh2020/ZKPcomponent/data_common"
	"github.com/krakenh2020/ZKPcomponent/key_management"
	"github.com/stretchr/testify/assert"
)

func TestEncDec(t *testing.T) {
	pubKey, secKey := key_management.GenerateKeypair()

	text := []byte("blafjdasklfjsaoifqweiuhfslkdvsadfkjnasdasdfsadfsadfffffffffffffffffffffffffffffsadffsagsdfgsdfgsdfgsdfgsdfg")
	encText, err := encryption.Encrypt(text, pubKey)
	if err != nil {
		t.Fatal(err)
	}
	decText, err := encryption.Decrypt(encText, pubKey, secKey)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, decText, text)
}

func TestEncVec(t *testing.T) {
	n := 100
	a, err := data_common.NewUniformRandomVector(n, data_common.MPCPrime)
	assert.NoError(t, err)

	pubKey, err := key_management.LoadPubKey("test", "../key_management/keys")
	assert.NoError(t, err)
	secKey, err := key_management.LoadSecKey("test", "../key_management/keys")
	assert.NoError(t, err)

	e, err := encryption.EncryptVec(a, pubKey)
	assert.NoError(t, err)

	d, err := encryption.DecVec(e, pubKey, secKey)
	assert.NoError(t, err)

	assert.Equal(t, a, d)
}
