package data_common

import (
	"fmt"
	"math"
)

func FloatToFixInt(x float64) (int64, error) {
	k := 41
	f := 20

	if math.Abs(x) >= math.Pow(2, float64(k-f-1)) {
		return 0, fmt.Errorf("float too big or to small")
	}

	v := int64(math.Round(x * math.Pow(2, 20)))

	return v, nil
}

func FixIntToFloat(i int64) (x float64) {
	v := float64(i) / math.Pow(2, 20)

	return v
}
