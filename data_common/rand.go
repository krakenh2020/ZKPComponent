package data_common

import (
	"crypto/rand"
	"math/big"
)

func NewUniformRandomVector(n int, max *big.Int) ([]*big.Int, error) {
	v := make([]*big.Int, n)
	var err error
	for i, _ := range v {
		v[i], err = rand.Int(rand.Reader, max)
		if err != nil {
			return nil, err
		}
	}
	return v, err
}

func NewUniformRangeRandomVector(n int, min *big.Int, max *big.Int) ([]*big.Int, error) {
	v := make([]*big.Int, n)
	var err error
	ran := new(big.Int).Sub(max, min)
	for i, _ := range v {
		v[i], err = rand.Int(rand.Reader, ran)
		if err != nil {
			return nil, err
		}
		v[i].Add(v[i], min)
	}
	return v, err
}
