package signature

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"

	"github.com/krakenh2020/ZKPcomponent/data_common"
	"github.com/krakenh2020/ZKPcomponent/signature/ec"
)

func CreateSharesShamirSpecial(input []*big.Int, r *big.Int) ([][]*big.Int, error) {
	res := make([][]*big.Int, 3)
	for i := int64(0); i < 3; i++ {
		res[i] = make([]*big.Int, len(input)*2+1)
	}

	hideMap := map[[3]int64][3]int64{
		[3]int64{1, -1, 1}:  {0, 1, 1},
		[3]int64{-1, 1, -1}: {0, -1, -1},
		[3]int64{0, -2, -1}: {0, 0, -1},
		[3]int64{0, 2, 1}:   {0, 0, 1},
		[3]int64{1, 1, 2}:   {-1, -1, -1},
		[3]int64{0, 0, 0}:   {0, 0, 0},
		[3]int64{1, 3, 3}:   {-2, -3, -3},
		[3]int64{2, 0, 3}:   {-1, 0, 0},
	}

	// linear function going through input[j]
	for j := 0; j < len(input); j++ {
		a, err := rand.Int(rand.Reader, data_common.MPCPrime)
		if err != nil {
			return nil, err
		}
		val := new(big.Int).Set(input[j])

		if new(big.Int).Abs(val).Cmp(data_common.MPCPrimeHalf) > 0 {
			return nil, fmt.Errorf("error: input value too big")
		}

		for i := int64(0); i < 3; i++ {
			res[i][j] = new(big.Int).Mul(a, big.NewInt(i+1))

			res[i][j].Add(val, res[i][j])
			res[i][j].Mod(res[i][j], data_common.MPCPrime)
		}

		hideP, err := rand.Int(rand.Reader, ec.P.Params().N)
		if err != nil {
			return nil, err
		}

		var check [3]int64
		check0 := new(big.Int).Mul(res[0][j], big.NewInt(2))
		check0.Sub(check0, res[1][j])
		check0.Div(check0, data_common.MPCPrime)
		check[0] = check0.Int64()

		check1 := new(big.Int).Mul(res[1][j], big.NewInt(3))
		check1.Sub(check1, new(big.Int).Mul(res[2][j], big.NewInt(2)))
		check1.Div(check1, data_common.MPCPrime)
		check[1] = check1.Int64()

		check2 := new(big.Int).Mul(res[0][j], big.NewInt(3))
		check2.Sub(check2, res[2][j])
		check2.Div(check2, data_common.MPCPrime)
		check[2] = check2.Int64()

		if val.Sign() < 0 {
			check[0]++
			check[1]++
			check[2]++
		}

		if _, ok := hideMap[check]; !ok {
			return nil, fmt.Errorf("unexpected envent in splitting the data")
		}

		for i := int64(0); i < 3; i++ {
			res[i][j+len(input)] = new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(hideP, big.NewInt(i+1)), big.NewInt(hideMap[check][i])), ec.P.Params().N)
		}
	}

	a, err := rand.Int(rand.Reader, data_common.MPCPrime)
	if err != nil {
		return nil, err
	}

	for i := int64(0); i < 3; i++ {
		res[i][2*len(input)] = new(big.Int).Mul(a, big.NewInt(i+1))
		val := new(big.Int).Set(r)

		res[i][2*len(input)].Add(val, res[i][2*len(input)])
		res[i][2*len(input)].Mod(res[i][2*len(input)], ec.P.Params().N)
	}

	return res, nil
}

func CommmitDataset(vec []*big.Int, r *big.Int) (*ec.Ec, *big.Int, error) {
	h := make([]*ec.Ec, len(vec))
	for i := 0; i < len(vec); i++ {
		h[i] = ec.HashIntoCurvePoint([]byte(strconv.Itoa(i)))
	}

	var err error
	if r == nil {
		r, err = rand.Int(rand.Reader, ec.P.Params().N)
		if err != nil {
			return nil, nil, err
		}
	}

	res := new(ec.Ec).ScalarBaseMult(r)
	hITovecI := new(ec.Ec)
	for i := 0; i < len(vec); i++ {
		val := new(big.Int).Set(vec[i])
		if new(big.Int).Abs(val).Cmp(data_common.MPCPrimeHalf) > 0 {
			return nil, nil, fmt.Errorf("error: input value too big")
		}

		hITovecI.ScalarMult(h[i], val)
		res.Add(res, hITovecI)
	}

	return res, r, nil
}

func CommitShareSpecial(vec []*big.Int) *ec.Ec {
	h := make([]*ec.Ec, (len(vec)-1)/2)
	for i := 0; i < len(h); i++ {
		h[i] = ec.HashIntoCurvePoint([]byte(strconv.Itoa(i)))
	}

	res := new(ec.Ec).ScalarBaseMult(vec[len(vec)-1])
	tmp := new(ec.Ec)
	tmpInt := new(big.Int)
	for i := 0; i < len(h); i++ {
		tmpInt.Mul(vec[i+len(vec)/2], data_common.MPCPrime)
		tmpInt.Add(tmpInt, vec[i])
		tmpInt.Mod(tmpInt, ec.P.Params().N)
		tmp.ScalarMult(h[i], tmpInt)
		res.Add(res, tmp)
	}

	return res
}

func JoinCommits(hSplit []*ec.Ec) (*ec.Ec, error) {
	check0 := new(ec.Ec).ScalarMult(hSplit[0], big.NewInt(2))
	neg := new(ec.Ec).Neg(hSplit[1])
	check0.Add(check0, neg)

	check1 := new(ec.Ec).ScalarMult(hSplit[1], big.NewInt(3))
	neg = new(ec.Ec).Neg(hSplit[2])
	neg.ScalarMult(neg, big.NewInt(2))
	check1.Add(check1, neg)
	if check1.Equal(check0) == false {
		return nil, fmt.Errorf("commits do not match")
	}

	check2 := new(ec.Ec).ScalarMult(hSplit[0], big.NewInt(3))
	neg = new(ec.Ec).Neg(hSplit[2])
	check2.Add(check2, neg)
	inverseN := new(big.Int).ModInverse(big.NewInt(2), ec.P.Params().N)
	check2.ScalarMult(check2, inverseN)
	if check2.Equal(check0) == false {
		return nil, fmt.Errorf("commits do not match")
	}

	return check0, nil
}
