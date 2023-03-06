package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/nacl/box"
)

type VecEnc struct {
	Key []byte
	Iv  []byte
	Val []byte
}

func EncryptVec(input []*big.Int, pubKey []byte) (*VecEnc, error) {
	inputBytes, err := json.Marshal(input)

	// prepare keys
	key := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, c.BlockSize())
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}
	encrypterCBC := cipher.NewCBCEncrypter(c, iv)

	msgByte := inputBytes
	// message is padded according to pkcs7 standard
	padLen := c.BlockSize() - (len(msgByte) % c.BlockSize())
	msgPad := make([]byte, len(msgByte)+padLen)
	copy(msgPad, msgByte)
	for i := len(msgByte); i < len(msgPad); i++ {
		msgPad[i] = byte(padLen)
	}

	symEnc := make([]byte, len(msgPad))
	encrypterCBC.CryptBlocks(symEnc, msgPad)

	// encrypt Key
	keyEnc, err := Encrypt(key, pubKey)
	if err != nil {
		return nil, err
	}

	return &VecEnc{Key: keyEnc, Iv: iv, Val: symEnc}, nil
}

func DecVec(encVec *VecEnc, pubKey, secKey []byte) ([]*big.Int, error) {
	// prepare keys
	key, err := Decrypt(encVec.Key, pubKey, secKey)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	msgPad := make([]byte, len(encVec.Val))
	decrypter := cipher.NewCBCDecrypter(c, encVec.Iv)
	decrypter.CryptBlocks(msgPad, encVec.Val)

	// unpad the message
	padLen := int(msgPad[len(msgPad)-1])
	if (len(msgPad) - padLen) < 0 {
		return nil, fmt.Errorf("failed to decrypt")
	}
	msgByte := msgPad[0:(len(msgPad) - padLen)]

	var res []*big.Int
	err = json.Unmarshal(msgByte, &res)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func Encrypt(input, pubkey []byte) ([]byte, error) {
	var key [32]byte
	copy(key[:], pubkey)
	encrypted, err := box.SealAnonymous(nil, input, &key, nil)
	return encrypted, err
}

// Decrypts a message
func Decrypt(message, inputPublicKey, inputPrivateKey []byte) ([]byte, error) {
	var publicKey [32]byte
	var privateKey [32]byte
	copy(publicKey[:], inputPublicKey)
	copy(privateKey[:], inputPrivateKey)
	out, ok := box.OpenAnonymous(nil, message, &publicKey, &privateKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}
	return out, nil
}
