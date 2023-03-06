package ZKPcomponent

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/krakenh2020/ZKPcomponent/signature"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	sig "github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/krakenh2020/ZKPcomponent/key_management"
	"github.com/stretchr/testify/assert"
)

func TestDatasetSplitAndZkpCsv(t *testing.T) {
	sig.Register(sig.EDDSA_BN254, eddsa.GenerateKeyInterfaces)
	signer, err := sig.EDDSA_BN254.New(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	//pubKey := signer.Public()

	sign, err := signature.SignCsv("datasets/framingham_small.csv", signer)
	if err != nil {
		t.Fatal(err)
	}
	err = signature.WriteSignCsv("datasets/framingham_small.csv", "datasets/framingham_small_signed.csv", sign)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	var circuit CircuitDataset
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	elapsed := time.Since(now)
	fmt.Println("ZKSign precompute1", elapsed.Milliseconds())
	if err != nil {
		t.Fatal(err)
	}
	now = time.Now()

	pk, vk, err := groth16.Setup(r1cs)
	elapsed = time.Since(now)
	fmt.Println("ZKSign precompute2", elapsed.Milliseconds())

	var buf bytes.Buffer
	var c []byte

	vkBytes, err := os.ReadFile("verifyKey.txt")
	err = json.Unmarshal(vkBytes, &c)

	//err = json.Unmarshal([]byte(VerifyKey), &c)
	if err != nil {
		t.Fatal(err)
	}
	buf.Write(c)

	vk3 := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk3.ReadFrom(&buf)

	buf.Reset()
	pkBytes, err := os.ReadFile("proofKey.txt")
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(pkBytes, &c)
	buf.Write(c)
	proofKey3 := groth16.NewProvingKey(ecc.BN254)
	_, err = proofKey3.ReadFrom(&buf)
	if err != nil {
		t.Fatal(err)
	}

	r1cs, err = frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)

	MPCpubKey, err := key_management.LoadPubKey("test", "key_management/keys")
	if err != nil {
		t.Fatal(err)
	}

	pubKeys := [][]byte{MPCpubKey, MPCpubKey, MPCpubKey}

	now = time.Now()
	split, proof, commits, cols, pubSig, err := DatasetSplitEncryptAndZkpCsvToFile("datasets/framingham_small_signed.csv", "datasets/framingham_small_signed_enc.txt", proofKey3, r1cs, pubKeys)
	if err != nil {
		t.Fatal(err)
	}
	elapsed = time.Since(now)
	fmt.Println("Split and ZKSign", elapsed.Milliseconds())
	_, _, _, _, _ = split, proof, commits, cols, pubSig

	aProof, err := ReadAuth("datasets/framingham_small_signed_enc.txt")
	if err != nil {
		t.Fatal(err)
	}

	proof2, commits2, sign2, pubKey2, err := ExpandAuthProof(aProof)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		now = time.Now()

		checkZKP, err := VerifyDatasetSplitAndZKpCsv(proof2, vk3, split[i], i, commits2, cols, sign2, pubKey2)
		if err != nil {
			t.Fatal(err)
		}
		assert.True(t, checkZKP)
		elapsed = time.Since(now)
		fmt.Println("ZKVerify", i, elapsed.Milliseconds())
	}

	//var buf bytes.Buffer
	buf.Reset()
	_, _ = r1cs.WriteTo(&buf)
	fmt.Println("r1cs", buf.Len())

	buf.Reset()
	_, _ = pk.WriteTo(&buf)
	fmt.Println("proofkey", buf.Len())

	//// write it
	//b := buf.Bytes()
	//a, _ := json.Marshal(b)
	//w, err := os.Create("proofKey.txt")
	//assert.NoError(t, err)
	//w.Write(a)
	//w.Close()
	//bb, err := json.Marshal(pk)
	//w, err = os.Create("proofKey2.txt")
	//assert.NoError(t, err)
	//w.Write(bb)
	//w.Close()

	buf.Reset()
	_, _ = vk.WriteTo(&buf)
	fmt.Println("verifykey", buf.Len())

	//// write it
	//b = buf.Bytes()
	//a, _ = json.Marshal(b)
	//w, err = os.Create("verifyKey.txt")
	//assert.NoError(t, err)
	//w.Write(a)
	//w.Close()

	buf.Reset()
	_, _ = proof.WriteTo(&buf)
	fmt.Println("proof", buf.Len())
}
