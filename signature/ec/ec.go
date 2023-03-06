package ec

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

type Ec struct {
	X *big.Int
	Y *big.Int
}

var P = elliptic.P256()

func (e *Ec) Set(x *Ec) *Ec {
	e.X = new(big.Int).Set(x.X)
	e.Y = new(big.Int).Set(x.Y)

	return e
}

func (e *Ec) Add(x, y *Ec) *Ec {
	e.X, e.Y = P.Add(x.X, x.Y, y.X, y.Y)

	return e
}

func (e *Ec) Neg(x *Ec) *Ec {
	e.X = new(big.Int).Set(x.X)
	e.Y = new(big.Int).Neg(x.Y)
	e.Y.Mod(e.Y, P.Params().P)

	return e
}

func (e *Ec) Gen() *Ec {
	e.X = new(big.Int).Set(P.Params().Gx)
	e.Y = new(big.Int).Set(P.Params().Gy)

	return e
}

func (e *Ec) Unit() *Ec {
	e.X = big.NewInt(0)
	e.Y = big.NewInt(0)

	return e
}

func (e *Ec) ScalarMult(x *Ec, k *big.Int) *Ec {
	kAbs := new(big.Int).Abs(k)
	e.X, e.Y = P.ScalarMult(x.X, x.Y, kAbs.Bytes())
	if k.Sign() < 0 {
		e.Neg(e)
	}

	return e
}

func (e *Ec) ScalarBaseMult(k *big.Int) *Ec {
	return e.ScalarMult(new(Ec).Gen(), k)
}

func (e *Ec) Random() (*Ec, error) {
	k, err := rand.Int(rand.Reader, P.Params().N)
	if err != nil {
		return nil, err
	}

	return e.ScalarMult(new(Ec).Gen(), k), nil
}

func (e *Ec) String() string {
	return e.X.String() + " " + e.Y.String()
}

func (e *Ec) XBytes() []byte {
	return e.X.Bytes()
}

func (e *Ec) Equal(x *Ec) bool {
	return e.X.Cmp(x.X) == 0 && e.Y.Cmp(x.Y) == 0
}

func tryPoint(r []byte) (x, y *big.Int) {
	hash := sha256.Sum256(r)
	x = new(big.Int).SetBytes(hash[:])

	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)

	x3.Sub(x3, threeX)
	x3.Add(x3, P.Params().B)

	y = x3.ModSqrt(x3, P.Params().P)
	return
}

func increment(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
}

func HashIntoCurvePoint(r []byte) *Ec {
	var x, y *big.Int
	t := make([]byte, 32)
	copy(t, r)

	x, y = tryPoint(t)
	for y == nil || !P.IsOnCurve(x, y) {
		increment(t)
		x, y = tryPoint(t)

	}
	return &Ec{X: x, Y: y}
}
