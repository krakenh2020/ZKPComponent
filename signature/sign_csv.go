package signature

import (
	"crypto/rand"

	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/krakenh2020/ZKPComponent/data_common"
	"github.com/krakenh2020/ZKPComponent/signature/ec"

	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
)

var G = &twistededwards.PointAffine{}
var H = &twistededwards.PointAffine{}

func init() {
	curve := twistededwards.GetEdwardsCurve()
	G.Set(&curve.Base)
	// H is a random element of the group, such that no one knows dlog of it
	H.X.SetString("8486526206644634594633280227502039915867387277038614969056409103126209864328")
	H.Y.SetString("4619243814969288950528155835091762356236797736539404666811148939109832492883")
}

type PedCommit struct {
	R *big.Int
	C *twistededwards.PointAffine
}

type SignatureZKP struct {
	Sig        []byte
	Commit     PedCommit
	CommitData *ec.Ec
	RData      *big.Int
	PubKey     []byte
}

func ParsePoint(buf []byte) twistededwards.PointAffine {
	var pointbn254 twistededwards.PointAffine
	pointbn254.SetBytes(buf[:32])
	return pointbn254
}

func ParseSignature(buf []byte) (twistededwards.PointAffine, []byte) {
	a := ParsePoint(buf)
	s := buf[32:]
	return a, s
}

func PedersenCommit(x *big.Int, rr *big.Int) (*PedCommit, error) {
	curve := twistededwards.GetEdwardsCurve()

	g := new(twistededwards.PointAffine).Set(G)
	h := new(twistededwards.PointAffine).Set(H)

	var r *big.Int
	var err error
	if rr != nil {
		r = rr
	} else {
		r, err = rand.Int(rand.Reader, &curve.Order)
		if err != nil {
			return nil, err
		}
	}

	gToX := new(twistededwards.PointAffine).ScalarMul(g, x)
	hToR := new(twistededwards.PointAffine).ScalarMul(h, r)
	c := new(twistededwards.PointAffine).Add(gToX, hToR)

	return &PedCommit{R: r, C: c}, nil
}

func MiMCPedersen(text [][]byte, rr *big.Int) (*PedCommit, error) {
	hs := hash.MIMC_BN254.New() // todo add seed to struct
	for i := 0; i < len(text); i++ {
		hs.Write(text[i])
	}
	miMCRes := hs.Sum(nil)
	miMCResInt := new(big.Int).SetBytes(miMCRes)

	commit, err := PedersenCommit(miMCResInt, rr)
	return commit, err
}

func CsvTextToVecAuth(csvTxt string) ([]*big.Int, []string, []float64, string, []byte, error) {
	lines := strings.Split(csvTxt, "\n")

	countLines := 0
	vec := make([]*big.Int, 0)
	vecFloat := make([]float64, 0)
	var cols []string
	for _, e := range lines {
		countLines++
		if e == "" {
			break
		}
		if countLines == 1 {
			cols = strings.Split(e, ",")
			continue
		}

		vals := strings.Split(e, ",")

		for _, e := range vals {
			f, err := strconv.ParseFloat(e, 64)
			if err != nil {
				return nil, nil, nil, "", nil, err
			}
			vecFloat = append(vecFloat, f)
			i, err := data_common.FloatToFixInt(f)
			if err != nil {
				return nil, nil, nil, "", nil, err
			}
			val := new(big.Int).SetInt64(i)

			vec = append(vec, val)
		}
	}

	if len(lines) == countLines {
		return vec, cols, vecFloat, "", nil, nil
	}

	if len(lines) == countLines+1 || (len(lines) == countLines+2 && lines[len(lines)-1] == "") {
		addText := lines[countLines]

		return vec, cols, vecFloat, addText, nil, nil
	}

	addText := lines[countLines]
	sig := []byte(lines[countLines+1])

	return vec, cols, vecFloat, addText, sig, nil
}

func CsvToVecAuth(file string) ([]*big.Int, []string, []float64, string, []byte, error) {
	csvBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, nil, "", nil, err
	}

	vec, cols, vecFloat, addText, sig, err := CsvTextToVecAuth(string(csvBytes))

	return vec, cols, vecFloat, addText, sig, err
}

func ColumnsCommitTextToBytes(columns []string, commit *ec.Ec, privateText string) ([][]byte, error) {
	textBytes := make([][]byte, 0)

	var valBytes []byte
	hashSha := sha256.New()
	_, err := hashSha.Write([]byte(strings.Join(columns, ",")))
	if err != nil {
		return nil, err
	}
	columnsHash := hashSha.Sum(nil)
	textBytes = append(textBytes, columnsHash)

	commitBytes := commit.XBytes()
	valBytes = make([]byte, 32)
	copy(valBytes[32-len(commitBytes):], commitBytes)
	textBytes = append(textBytes, valBytes)

	hashSha.Reset()
	_, err = hashSha.Write([]byte(privateText))
	if err != nil {
		return nil, err
	}
	privateTextHash := hashSha.Sum(nil)

	textBytes = append(textBytes, privateTextHash)

	return textBytes, nil
}

func SignCsv(file string, signer signature.Signer) (*SignatureZKP, error) {
	vec, cols, _, privateText, sigTest, err := CsvToVecAuth(file)
	if err != nil {
		return nil, err
	}
	if sigTest != nil {
		return nil, fmt.Errorf("data already signed")
	}

	commit, r, err := CommmitDataset(vec, nil)
	if err != nil {
		return nil, err
	}

	textBytes, err := ColumnsCommitTextToBytes(cols, commit, privateText)
	if err != nil {
		return nil, err
	}

	mimcPed, err := MiMCPedersen(textBytes, nil)
	if err != nil {
		return nil, err
	}

	hFunc := hash.MIMC_BN254.New()

	hashed := mimcPed.C.X.Bytes()
	sign, err := signer.Sign(hashed[:], hFunc)
	if err != nil {
		return nil, err
	}

	return &SignatureZKP{Sig: sign, Commit: *mimcPed, CommitData: commit, RData: r, PubKey: signer.Public().Bytes()}, nil
}

func WriteSignCsv(fileInput, fileOutput string, s *SignatureZKP) error {
	bytesIn, err := os.ReadFile(fileInput)
	if err != nil {
		return err
	}
	if bytesIn[len(bytesIn)-1] != byte('\n') {
		bytesIn = append(bytesIn, byte('\n'))
	}

	vec, cols, _, _, _, err := CsvToVecAuth(fileInput)
	if err != nil {
		return err
	}
	lenData := len(vec) / len(cols)

	linesIn := len(strings.Split(string(bytesIn), "\n"))
	if linesIn == lenData+2 {
		bytesIn = append(bytesIn, byte('\n'))
		bytesIn = append(bytesIn, byte('\n'))
	}
	if linesIn == lenData+3 {
		bytesIn = append(bytesIn, byte('\n'))
	}

	sigBytes, err := json.Marshal(s)
	if err != nil {
		return err
	}

	bytesOut := append(bytesIn, sigBytes...)
	bytesOut = append(bytesOut, byte('\n'))

	f, err := os.Create(fileOutput)
	if err != nil {
		return err
	}
	_, err = f.Write(bytesOut)

	return err
}

func VerifyCsv(file string, pubKey signature.PublicKey) (bool, error) {
	vec, cols, _, privateText, signBytes, err := CsvToVecAuth(file)
	if err != nil {
		return false, err
	}

	var sign SignatureZKP
	err = json.Unmarshal(signBytes, &sign)
	if err != nil {
		return false, err
	}
	for i, e := range pubKey.Bytes() {
		if sign.PubKey[i] != e {
			return false, fmt.Errorf("public keys do not match")
		}
	}

	commit, _, err := CommmitDataset(vec, sign.RData)

	if commit.Equal(sign.CommitData) == false {
		return false, fmt.Errorf("commit value and data do not match")
	}

	textBytes, err := ColumnsCommitTextToBytes(cols, commit, privateText)

	mimcPed, err := MiMCPedersen(textBytes, sign.Commit.R)
	if err != nil {
		return false, err
	}

	hFunc := hash.MIMC_BN254.New()
	hashed := mimcPed.C.X.Bytes()
	check, err := pubKey.Verify(sign.Sig, hashed[:], hFunc)

	return check, err
}
