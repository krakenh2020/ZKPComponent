package ZKPcomponent

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/krakenh2020/ZKPcomponent/signature"
	"math/big"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	sig "github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/krakenh2020/ZKPcomponent/data_common"
	"github.com/krakenh2020/ZKPcomponent/encryption"
	"github.com/krakenh2020/ZKPcomponent/signature/ec"
)

type AuthProof struct {
	ZkProof []byte
	Commits []*ec.Ec
	Sign    *signature.SignatureZKP
}

func ColumnsCommitTextAssign(columns []string, commit *ec.Ec, privateText string, witness *CircuitDataset, private bool) error {
	var valBytes []byte
	hashSha := sha256.New()
	_, err := hashSha.Write([]byte(strings.Join(columns, ",")))
	if err != nil {
		return err
	}
	columnsHash := hashSha.Sum(nil)
	witness.ColsHash = columnsHash

	commitBytes := commit.XBytes()
	valBytes = make([]byte, 32)
	copy(valBytes[32-len(commitBytes):], commitBytes)
	witness.Commit = valBytes

	if private {
		hashSha.Reset()
		_, err = hashSha.Write([]byte(privateText))
		if err != nil {
			return err
		}
		privateTextHash := hashSha.Sum(nil)
		witness.SecTextHash = privateTextHash
	}

	return nil
}

func DatasetSplitAndZkpCsvText(vec []*big.Int, cols []string, privateText string, signBytes []byte, proofKey groth16.ProvingKey,
	r1cs frontend.CompiledConstraintSystem) ([][]*big.Int, groth16.Proof, []*ec.Ec, *signature.SignatureZKP, error) {

	var sign signature.SignatureZKP
	err := json.Unmarshal(signBytes, &sign)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	splits, err := signature.CreateSharesShamirSpecial(vec, sign.RData)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	commits := make([]*ec.Ec, 3)
	commits[0] = signature.CommitShareSpecial(splits[0])
	commits[1] = new(ec.Ec).ScalarMult(commits[0], big.NewInt(2))
	commits[1] = new(ec.Ec).Add(commits[1], new(ec.Ec).Neg(sign.CommitData))
	commits[2] = new(ec.Ec).ScalarMult(commits[0], big.NewInt(3))
	commits[2] = new(ec.Ec).Add(commits[2], new(ec.Ec).Neg(new(ec.Ec).ScalarMult(sign.CommitData, big.NewInt(2))))

	var circuit CircuitDataset

	// assign cols
	err = ColumnsCommitTextAssign(cols, sign.CommitData, privateText, &circuit, true)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	circuit.R = sign.Commit.R

	pubkey2 := signature.ParsePoint(sign.PubKey)
	circuit.PublicKey.X = pubkey2.X
	circuit.PublicKey.Y = pubkey2.Y

	sig2, sigS := signature.ParseSignature(sign.Sig)
	circuit.Signature.R.X = sig2.X
	circuit.Signature.R.Y = sig2.Y
	circuit.Signature.S = sigS

	witness, err := frontend.NewWitness(&circuit, ecc.BN254)
	proof, err := groth16.Prove(r1cs, proofKey, witness)

	// make sig public
	sign.Commit.R = nil

	return splits, proof, commits, &sign, err
}

func CsvTextSplitAndZkpCsvText(csvText string, proofKey groth16.ProvingKey, r1cs frontend.CompiledConstraintSystem) ([][]*big.Int,
	groth16.Proof, []*ec.Ec, []string, *signature.SignatureZKP, error) {
	vec, cols, _, privateText, signBytes, err := signature.CsvTextToVecAuth(csvText)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	splits, proof, commits, sign, err := DatasetSplitAndZkpCsvText(vec, cols, privateText, signBytes, proofKey, r1cs)

	return splits, proof, commits, cols, sign, err
}

func DatasetSplitAndZkpCsv(file string, proofKey groth16.ProvingKey, r1cs frontend.CompiledConstraintSystem) ([][]*big.Int,
	groth16.Proof, []*ec.Ec, []string, *signature.SignatureZKP, error) {
	csvBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	splits, proof, commits, cols, sign, err := CsvTextSplitAndZkpCsvText(string(csvBytes), proofKey, r1cs)

	return splits, proof, commits, cols, sign, err
}

func DatasetSplitEncryptAndZkpCsvToFile(file, output string, proofKey groth16.ProvingKey, r1cs frontend.CompiledConstraintSystem,
	pubKeys [][]byte) ([][]*big.Int, groth16.Proof, []*ec.Ec, []string, *signature.SignatureZKP, error) {
	shares, proof, commits, cols, sign, err := DatasetSplitAndZkpCsv(file, proofKey, r1cs)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	w, err := os.Create(output)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	for i := int64(0); i < 3; i++ {
		msg, err := encryption.EncryptVec(shares[i], pubKeys[i])
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		write, err := json.Marshal(msg)

		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		_, err = w.Write(write)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		_, err = w.Write([]byte("\n"))
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
	}
	_, err = w.Write([]byte(strings.Join(cols, ",") + "\n"))
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	sign.RData = nil

	var buf bytes.Buffer
	_, err = proof.WriteTo(&buf)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	aProof := AuthProof{ZkProof: buf.Bytes(), Commits: commits, Sign: sign}
	aProofBytes, err := json.Marshal(aProof)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	_, err = w.Write(aProofBytes)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	_, err = w.Write([]byte("\n"))
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	err = w.Close()

	return shares, proof, commits, cols, sign, err
}

func ExpandAuthProof(aProof *AuthProof) (groth16.Proof, []*ec.Ec, *signature.SignatureZKP, sig.PublicKey, error) {
	var buf bytes.Buffer
	_, err := buf.Write(aProof.ZkProof)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	var proof groth16.Proof
	proof = groth16.NewProof(ecc.BN254)
	_, err = proof.ReadFrom(&buf)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	var pubKey eddsa.PublicKey
	_, err = pubKey.SetBytes(aProof.Sign.PubKey)

	return proof, aProof.Commits, aProof.Sign, &pubKey, nil
}

func ReadAuth(file string) (*AuthProof, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(f)

	for i := 0; i < 4; i++ {
		_, err = data_common.Readln(reader)
		if err != nil {
			return nil, err
		}
	}
	// zkp info
	zkpString, err := data_common.Readln(reader)
	if err != nil {
		return nil, err
	}
	err = f.Close()
	if err != nil {
		return nil, err
	}

	var aProof AuthProof
	err = json.Unmarshal([]byte(zkpString), &aProof)
	if err != nil {
		return nil, err
	}

	return &aProof, nil
}

func VerifyDatasetSplitAndZKpCsv(proof groth16.Proof, verKey groth16.VerifyingKey, splitI []*big.Int, id int, commits []*ec.Ec, cols []string,
	sig *signature.SignatureZKP, pubKey sig.PublicKey) (bool, error) {
	// verify the signature
	var circuit CircuitDataset

	commit, err := signature.JoinCommits(commits)
	if err != nil {
		return false, err
	}

	err = ColumnsCommitTextAssign(cols, commit, "", &circuit, false)
	if err != nil {
		return false, err
	}

	// todo assert that the pubkey is the same
	pubkey2 := signature.ParsePoint(pubKey.Bytes())
	circuit.PublicKey.X = pubkey2.X
	circuit.PublicKey.Y = pubkey2.Y

	sig2, sigS := signature.ParseSignature(sig.Sig)
	circuit.Signature.R.X = sig2.X
	circuit.Signature.R.Y = sig2.Y
	circuit.Signature.S = sigS

	publicWitness, err := frontend.NewWitness(&circuit, ecc.BN254, frontend.PublicOnly())
	err = groth16.Verify(proof, verKey, publicWitness)
	if err != nil {
		return false, err
	}

	// verify the commit
	partCommit := signature.CommitShareSpecial(splitI)
	if partCommit.Equal(commits[id]) == false {
		return false, fmt.Errorf("commit of the split does not match encrypted values")
	}

	return true, nil
}
