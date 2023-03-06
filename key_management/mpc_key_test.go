package key_management_test

import (
	"testing"

	"github.com/krakenh2020/ZKPcomponent/key_management"
	"github.com/stretchr/testify/assert"
)

func TestKeyGenLoad(t *testing.T) {
	secKey, pubKey, err := key_management.NewKeyPair("test2", "keys")
	if err != nil {
		t.Fatal(err)
	}

	pubKey2, err := key_management.LoadPubKey("test2", "keys")
	if err != nil {
		t.Fatal(err)
	}

	secKey2, err := key_management.LoadSecKey("test2", "keys")
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, pubKey, pubKey2)
	assert.Equal(t, secKey, secKey2)
}
