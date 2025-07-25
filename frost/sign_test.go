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
	th, n := 3, 5
	dkgs := dkgProtocol(t, th, n)
	assert.Equal(t, n, len(dkgs))
	sa := NewSA(th, dkgs[0].ids, dkgs[0].Commitments)
	//	签名预处理
	sigMaxTimes := 10
	for i := 0; i < n; i++ {
		delist := dkgs[i].Preprocess(sigMaxTimes)
		assert.NotNil(t, delist)
		assert.Equal(t, delist.index, dkgs[i].index)
		assert.True(t, delist.id.IsEqual(&dkgs[i].id))
		assert.Equal(t, sigMaxTimes, len(delist.D))
		assert.Equal(t, sigMaxTimes, len(delist.E))
		sa.SaveDElist(dkgs[i].index, delist)
	}
	//	create signer set for signature share
	signerSet := sa.CreateSignerSet("frost", 1, []int{2, 3, 1})
	assert.NotNil(t, signerSet)
	assert.Equal(t, "frost", signerSet.m)
	assert.Equal(t, 1, signerSet.signCounter)
	var zis []*Sign
	for _, index := range signerSet.indexSet {
		sig := dkgs[index].Sign(signerSet)
		assert.Equal(t, index, sig.index)
		assert.Nil(t, sig.R)
		zis = append(zis, sig)
	}
	rz, err := sa.SignAgg(signerSet, zis)
	assert.NoError(t, err)
	fg := VerifyAgg(signerSet.m, sa.grpPubKey, rz)
	assert.True(t, fg)
}
func TestLagrangeCoefficient(t *testing.T) {
	// f(x)=2+x+x^2
	var f0 bls.SecretKey
	f0.SetDecString("2")
	var id1, id2, id3, id4 bls.ID
	var y1, y2, y3, y4, out bls.SecretKey
	id1.SetDecString("1")
	id2.SetDecString("2")
	id3.SetDecString("3")
	id4.SetDecString("4")
	y1.SetDecString("4")
	y2.SetDecString("8")
	y3.SetDecString("14")
	y4.SetDecString("22")
	err := out.Recover([]bls.SecretKey{y1, y2}, []bls.ID{id1, id2})
	assert.NoError(t, err)
	// 点太少，恢复不出来
	assert.False(t, out.IsEqual(&f0))
	err = out.Recover([]bls.SecretKey{y1, y2, y3}, []bls.ID{id1, id2, id3})
	assert.NoError(t, err)
	assert.True(t, out.IsEqual(&f0))
	out.SetDecString("0")
	err = out.Recover([]bls.SecretKey{y4, y2, y3}, []bls.ID{id4, id2, id3})
	assert.NoError(t, err)
	assert.True(t, out.IsEqual(&f0))
	err = out.Recover([]bls.SecretKey{y4, y2, y3, y1}, []bls.ID{id4, id2, id3, id1})
	assert.NoError(t, err)
	assert.True(t, out.IsEqual(&f0))

	ss := &SignerSet{indexSet: []int{3, 1, 2},
		dEUsing: map[int]*iDDE{3: &iDDE{id: &id4}, 1: &iDDE{id: &id2}, 2: &iDDE{id: &id3}},
	}
	h4 := LagrangeCoefficient(3, ss)
	h2 := LagrangeCoefficient(1, ss)
	h3 := LagrangeCoefficient(2, ss)
	fmt.Printf("h4:%+v\n", h4.GetDecString()) //3
	fmt.Printf("h2:%+v\n", h2.GetDecString()) //6
	fmt.Printf("h3:%+v\n", h3.GetDecString()) //-8

	h104 := SkMul(h4, &y4)
	h102 := SkMul(h2, &y2)
	h103 := SkMul(h3, &y3)
	h104.Add(h102)
	h104.Add(h103)
	assert.True(t, h104.IsEqual(&f0))

}

func TestFrLagrangeInterpolation(t *testing.T) {
	// f(x)=2+x+x^2
	var f0 bls.Fr
	f0.SetInt64(2)
	var out, x1, x2, x3, y1, y2, y3 bls.Fr
	x1.SetString("1", 10)
	x2.SetString("2", 10)
	x3.SetString("3", 10)
	y1.SetString("4", 10)
	y2.SetString("8", 10)
	y3.SetString("14", 10)
	err := bls.FrLagrangeInterpolation(&out, []bls.Fr{x1, x2, x3}, []bls.Fr{y1, y2, y3})
	assert.NoError(t, err)
	assert.True(t, out.IsEqual(&f0))

	var xx, xx2, out2 bls.Fr
	//|G2|=52435875175126190479447740508185965837690552500527637822603658699938581184513
	//     52435875175126190479447740508185965837690552500527637822603658699938581184512
	xx.SetString("52435875175126190479447740508185965837690552500527637822603658699938581184510", 10) //-3
	xx2.SetInt64(3)
	out2.SetInt64(77)
	bls.FrAdd(&out2, &xx, &xx2)
	assert.True(t, out2.IsZero())

}
