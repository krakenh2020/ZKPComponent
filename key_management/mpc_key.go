package key_management

import (
	"crypto/rand"
	"os"

	"golang.org/x/crypto/nacl/box"
)

func GenerateKeypair() (publicKey, privateKey []byte) {
	publicKeyTmp, privateKeyTmp, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	publicKey = publicKeyTmp[:]
	privateKey = privateKeyTmp[:]
	return
}

func NewKeyPair(name, loc string) ([]byte, []byte, error) {
	publicKey, privateKey := GenerateKeypair()

	f1, err := os.Create(loc + "/" + name + "_pub.txt")
	if err != nil {
		return nil, nil, err
	}
	_, err = f1.Write(publicKey)
	if err != nil {
		return nil, nil, err
	}
	err = f1.Close()
	if err != nil {
		return nil, nil, err
	}

	f2, err := os.Create(loc + "/" + name + "_sec.txt")
	if err != nil {
		return nil, nil, err
	}
	_, err = f2.Write(privateKey)
	if err != nil {
		return nil, nil, err
	}
	err = f2.Close()
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

func LoadPubKey(name, loc string) ([]byte, error) {
	f1, err := os.Open(loc + "/" + name + "_pub.txt")
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 32)
	_, err = f1.Read(buf)

	return buf, err
}

func LoadSecKey(name, loc string) ([]byte, error) {
	f1, err := os.Open(loc + "/" + name + "_sec.txt")
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 32)
	_, err = f1.Read(buf)

	return buf, err
}
