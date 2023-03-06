package data_common

import "math/big"

var MPCPrime, _ = new(big.Int).SetString("340282366920938463463374607431768211507", 10)
var MPCPrimeHalf = new(big.Int).Div(MPCPrime, big.NewInt(2))
