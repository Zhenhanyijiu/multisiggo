package frost

import (
	"fmt"
	"github.com/herumi/bls/ffi/go/bls"
	"github.com/stretchr/testify/assert"
	"testing"
)

func dkgProtocol(t *testing.T, th, n int) []Dkg {
	//th, n := 3, 5
	dkgs := make([]Dkg, n)
	//每个参与者生成多项式
	for i := 0; i < n; i++ {
		dkgs[i].Set(th, n, GetIDList(i, n))
		assert.Equal(t, n, dkgs[i].n)
		assert.Equal(t, th, dkgs[i].t)
	}
	//生成知识证明,广播承诺和知识证明
	var prfs []*Poof
	var coms [][]bls.PublicKey //所有的commitment
	for i := 0; i < n; i++ {
		prf, err := dkgs[i].GenProof()
		assert.NoError(t, err)
		prfs = append(prfs, prf)
		coms = append(coms, dkgs[i].mpk)
	}
	assert.Equal(t, n, len(prfs))
	assert.Equal(t, n, len(coms))
	// 接收知识证明和承诺，并验证
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if j != i {
				dkgs[i].SaveCommitment(j, coms[j])
			}
			//	check
			fg, err := ZkVerify(&dkgs[i].ids[j], &dkgs[i].Commitments[j][0], prfs[j])
			assert.NoError(t, err)
			assert.True(t, fg)
		}
	}
	//计算 share 并发送
	for i := 0; i < n; i++ {
		shares := dkgs[i].GenSecretShare()
		assert.Equal(t, n, len(shares))
		for j := 0; j < n; j++ {
			if j != i {
				fg := VerifySecretShare(&dkgs[j].id, &shares[j], dkgs[j].Commitments[i])
				assert.True(t, fg)
				fmt.Printf("--------- p%+v=>p%+v f%+v(%+v)\n", i, j, i, dkgs[j].id.GetDecString())
				dkgs[j].AddSecretShare(&shares[j])
			}
		}
		fmt.Println()
	}
	//	计算所需密钥
	for i := 0; i < n; i++ {
		dkgs[i].GenSignKey()
	}
	// check
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if j != i {
				fg := dkgs[i].sigPubKey.IsEqual(&dkgs[j].sigPubKeys[i])
				assert.True(t, fg)
			}
		}
		assert.True(t, dkgs[0].grpPubKey.IsEqual(dkgs[i].grpPubKey))
	}

	return dkgs
}
func TestSA(t *testing.T) {
	th, n := 2, 3
	dkgs := dkgProtocol(t, th, n)
	assert.Equal(t, n, len(dkgs))
	sa := NewSA(th, n, dkgs[0].grpPubKey, dkgs[0].sigPubKeys)
	//	签名预处理
	counters := 10
	for i := 0; i < n; i++ {
		delist := dkgs[i].Preprocess(counters)
		assert.NotNil(t, delist)
		assert.Equal(t, delist.index, dkgs[i].index)
		assert.True(t, delist.id.IsEqual(&dkgs[i].id))
		assert.Equal(t, counters, len(delist.D))
		assert.Equal(t, counters, len(delist.E))
		sa.SaveDElist(dkgs[i].index, delist)
	}
	//	create signer set for signature share
	signerSet := sa.CreateSignerSet("frost", 1, []int{0, 1})
	assert.NotNil(t, signerSet)
	assert.Equal(t, "frost", signerSet.m)
	assert.Equal(t, 1, signerSet.signCounter)
	var zis []*Sign
	for _, index := range signerSet.indexSet {
		fmt.Printf("--------- 签名者的 index:%+v\n", index)
		sig := dkgs[index].Sign(signerSet)
		assert.Equal(t, index, sig.index)
		assert.Nil(t, sig.R)
		zis = append(zis, sig)
	}
	rz, err := sa.SignAgg(signerSet, zis)
	assert.NoError(t, err)
	c := H2(signerSet.m, rz.R, sa.grpPubKey)
	fmt.Printf("c :%+v\n", c.GetDecString())
	fg := IsValid(rz.R, sa.grpPubKey, rz.z, c)
	assert.True(t, fg)
}
func TestLagrangeCoefficient(t *testing.T) {
	var id1, id2, id3 bls.ID
	var y1, y2, y3, out bls.SecretKey
	id1.SetDecString("1")
	id2.SetDecString("2")
	id3.SetDecString("3")
	y1.SetDecString("4")
	y2.SetDecString("8")
	y3.SetDecString("14")
	err := out.Recover([]bls.SecretKey{y1, y2, y3}, []bls.ID{id1, id2, id3})
	assert.NoError(t, err)
	assert.Equal(t, "2", out.GetDecString())
	ss := &SignerSet{indexSet: []int{0, 1, 2},
		dEUsing: map[int]*iDDE{0: &iDDE{id: &id1}, 1: &iDDE{id: &id2}, 2: &iDDE{id: &id3}},
	}
	h1 := LagrangeCoefficient(0, ss)
	h2 := LagrangeCoefficient(1, ss)
	h3 := LagrangeCoefficient(2, ss)
	fmt.Printf("h1:%+v\n", h1.GetDecString())
	fmt.Printf("h2:%+v\n", h2.GetDecString())
	fmt.Printf("h3:%+v\n", h3.GetDecString())

	h101 := SkMul(h1, &y1)
	h102 := SkMul(h2, &y2)
	h103 := SkMul(h3, &y3)
	h101.Add(h102)
	h101.Add(h103)
	fmt.Printf("h101:%+v\n", h101.GetDecString())

}
