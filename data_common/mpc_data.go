package data_common

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/krakenh2020/ZKPcomponent/encryption"
)

// CreateSharesShamir is a helping function that splits a vector
// input into 3 random parts x_1, x_2, x_3, such that
// f(i) = x_i and f(0) = x, for a linear f
func CreateSharesShamir(input []*big.Int) ([][]*big.Int, error) {
	// f(i) = ai + x
	a, err := NewUniformRandomVector(len(input), MPCPrime)
	if err != nil {
		return nil, err
	}

	res := make([][]*big.Int, 3)
	for i := int64(0); i < 3; i++ {
		res[i] = make([]*big.Int, len(input))
		// linear function going through input[j]
		for j := 0; j < len(input); j++ {
			res[i][j] = new(big.Int).Mul(a[j], big.NewInt(i+1))
			val := new(big.Int).Set(input[j])
			if new(big.Int).Abs(val).Cmp(MPCPrimeHalf) > 0 {
				return nil, fmt.Errorf("error: input value too big")
			}
			// in case input is negative
			if val.Sign() < 0 {
				val.Add(MPCPrime, val)
			}
			res[i][j].Add(val, res[i][j])
			res[i][j].Mod(res[i][j], MPCPrime)
		}
	}

	return res, nil
}

func JoinSharesShamir(input [][]*big.Int) ([]*big.Int, error) {
	res := make([]*big.Int, len(input[0]))

	for i, _ := range input[0] {
		res[i] = new(big.Int).Mul(input[0][i], big.NewInt(2))
		res[i].Sub(res[i], input[1][i])
		res[i].Mod(res[i], MPCPrime)

		check := new(big.Int).Mul(input[1][i], big.NewInt(3))
		check.Sub(check, new(big.Int).Mul(input[2][i], big.NewInt(2)))
		check.Mod(check, MPCPrime)
		if check.Cmp(res[i]) != 0 {
			return nil, fmt.Errorf("joining faild, inconsistent shares")
		}

		check2 := new(big.Int).Mul(input[0][i], big.NewInt(3))
		check2.Sub(check2, input[2][i])
		check2.Mod(check2, MPCPrime)
		twiceRI := new(big.Int).Mul(res[i], big.NewInt(2))
		twiceRI.Mod(twiceRI, MPCPrime)
		if check2.Cmp(twiceRI) != 0 {
			return nil, fmt.Errorf("joining faild, inconsistent shares")
		}

		if res[i].Cmp(MPCPrimeHalf) > 0 {
			res[i].Sub(res[i], MPCPrime)
		}
	}

	return res, nil
}

func JoinSharesShamirFloat(input [][]*big.Int) []float64 {
	res := make([]float64, len(input[0]))

	for i, _ := range input[0] {
		f := new(big.Int).Mul(input[0][i], big.NewInt(2))
		f.Sub(f, input[1][i])
		f.Mod(f, MPCPrime)
		if f.Cmp(MPCPrimeHalf) > 0 {
			f.Sub(f, MPCPrime)
		}
		res[i] = FixIntToFloat(f.Int64())
	}

	return res
}

func CsvToVec(file string) ([]*big.Int, []string, []float64, error) {
	text, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, nil, err
	}

	vec, cols, vecFloat, err := CsvTextToVec(string(text))

	return vec, cols, vecFloat, err
}

func CsvTextToVec(csvTxt string) ([]*big.Int, []string, []float64, error) {
	lines := strings.Split(csvTxt, "\n")

	countLines := 0
	vec := make([]*big.Int, 0)
	vecFloat := make([]float64, 0)
	var cols []string
	for _, e := range lines {
		countLines++
		if countLines == 1 {
			cols = strings.Split(e, ",")
			continue
		}
		if e == "" {
			continue
		}

		vals := strings.Split(e, ",")

		for _, e := range vals {
			f, err := strconv.ParseFloat(e, 64)
			if err != nil {
				return nil, nil, nil, err
			}
			vecFloat = append(vecFloat, f)
			i, err := FloatToFixInt(f)
			if err != nil {
				return nil, nil, nil, err
			}
			val := new(big.Int).SetInt64(i)

			vec = append(vec, val)
		}
	}

	return vec, cols, vecFloat, nil
}

func SplitCsvFile(file, output string, pubKeys [][]byte) ([]float64, [][]*big.Int, []string, error) {
	vec, cols, vecFloat, err := CsvToVec(file)
	if err != nil {
		return nil, nil, nil, err
	}

	shares, err := CreateSharesShamir(vec)
	if err != nil {
		return nil, nil, nil, err
	}

	w, err := os.Create(output)
	if err != nil {
		return nil, nil, nil, err
	}

	for i := int64(0); i < 3; i++ {
		msg, err := encryption.EncryptVec(shares[i], pubKeys[i])
		if err != nil {
			return nil, nil, nil, err
		}
		write, err := json.Marshal(msg)

		if err != nil {
			return nil, nil, nil, err
		}

		_, err = w.Write(write)
		if err != nil {
			return nil, nil, nil, err
		}
		_, err = w.Write([]byte("\n"))
		if err != nil {
			return nil, nil, nil, err
		}
	}
	_, err = w.Write([]byte(strings.Join(cols, ",") + "\n"))
	if err != nil {
		return nil, nil, nil, err
	}
	err = w.Close()

	return vecFloat, shares, cols, err
}

func DeleteShare(filePath string) error {
	cmdStr := "rm " + filePath
	cmd := exec.Command("bash", "-c", cmdStr)
	out := new(bytes.Buffer)
	outErr := new(bytes.Buffer)
	cmd.Stdout = out
	cmd.Stderr = outErr

	err := cmd.Run()

	return err
}

func ReadShare(file string, pubKey, secKey []byte, nodeId int) ([]*big.Int, []string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, nil, err
	}

	reader := bufio.NewReader(f)

	countLines := 0
	var decVec []*big.Int
	for countLines < 3 {
		text, err := Readln(reader)

		if countLines != nodeId {
			countLines++
			continue
		}

		var encVec encryption.VecEnc
		err = json.Unmarshal([]byte(text), &encVec)
		if err != nil {
			return nil, nil, err
		}

		decVec, err = encryption.DecVec(&encVec, pubKey, secKey)
		if err != nil {
			return nil, nil, err
		}
		countLines++
	}
	// columns info
	text, err := Readln(reader)
	cols := strings.Split(text, ",")

	f.Close()

	return decVec, cols, nil
}
