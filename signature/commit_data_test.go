package signature

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/krakenh2020/ZKPcomponent/data_common"
	"github.com/krakenh2020/ZKPcomponent/signature/ec"
	"github.com/stretchr/testify/assert"
)

func TestCommmitDataset(t *testing.T) {
	v, err := data_common.NewUniformRangeRandomVector(10000, new(big.Int).Neg(data_common.MPCPrimeHalf), data_common.MPCPrimeHalf)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	h, r, err := CommmitDataset(v, nil)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(now)
	fmt.Println("commit in milliseconds", elapsed.Milliseconds())

	split, err := CreateSharesShamirSpecial(v, r)
	if err != nil {
		t.Fatal(err)
	}
	hSplit := make([]*ec.Ec, 3)

	for i := 0; i < 3; i++ {
		hSplit[i] = CommitShareSpecial(split[i])
	}

	hCheck, err := JoinCommits(hSplit)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, hCheck.Equal(h))
}
