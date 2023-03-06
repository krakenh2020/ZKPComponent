package ZKPComponent

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/krakenh2020/ZKPComponent/signature"
)

type CircuitDataset struct {
	// text
	ColsHash    frontend.Variable `gnark:",public"`
	Commit      frontend.Variable `gnark:",public"`
	SecTextHash frontend.Variable
	// Pedersen
	R frontend.Variable
	// Signature
	PublicKey twistededwards.Point `gnark:",public"`
	Signature Signature            `gnark:",public"`
}

type Signature struct {
	R twistededwards.Point
	S frontend.Variable
}

func (circuit *CircuitDataset) Define(api frontend.API) error {
	// hash with MiMC
	miMC, _ := mimc.NewMiMC(api)
	miMC.Write(circuit.ColsHash)
	miMC.Write(circuit.Commit)
	miMC.Write(circuit.SecTextHash)

	miMCres := miMC.Sum()

	// Pedersen commit
	curve, err := twistededwards.NewEdCurve(ecc.BN254)
	if err != nil {
		return err
	}

	g := &twistededwards.Point{signature.G.X, signature.G.Y}
	gX := &twistededwards.Point{}
	gX.X = curve
	gX.ScalarMul(api, g, miMCres, curve)
	gX.MustBeOnCurve(api, curve)

	h := &twistededwards.Point{signature.H.X, signature.H.Y}
	hR := &twistededwards.Point{}
	hR.ScalarMul(api, h, circuit.R, curve)
	hR.MustBeOnCurve(api, curve)

	c := &twistededwards.Point{}
	c.Add(api, gX, hR, curve)
	c.MustBeOnCurve(api, curve)

	// compute H(RData, A, M), all parameters in data are in Montgomery form
	data := []frontend.Variable{
		circuit.Signature.R.X,
		circuit.Signature.R.Y,
		circuit.PublicKey.X,
		circuit.PublicKey.Y,
		c.X,
	}
	miMC.Reset()
	miMC.Write(data...)
	hramConstant := miMC.Sum()

	base := twistededwards.Point{}
	base.X = curve.Base.X
	base.Y = curve.Base.Y

	// lhs = [S]G
	lhs := twistededwards.Point{}
	lhs.ScalarMul(api, &base, circuit.Signature.S, curve)
	lhs.MustBeOnCurve(api, curve)

	rhs := twistededwards.Point{}
	rhs.ScalarMul(api, &circuit.PublicKey, hramConstant, curve).Add(api, &rhs, &circuit.Signature.R, curve)

	rhs.MustBeOnCurve(api, curve)

	// lhs-rhs
	rhs.Neg(api, &rhs).Add(api, &lhs, &rhs, curve)

	// [cofactor](lhs-rhs), cofactor = 8
	rhs.Double(api, &rhs, curve).
		Double(api, &rhs, curve).Double(api, &rhs, curve)

	api.AssertIsEqual(rhs.X, 0)
	api.AssertIsEqual(rhs.Y, 1)

	return nil
}
