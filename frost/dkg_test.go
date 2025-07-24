package frost

import (
	"fmt"
	"github.com/herumi/bls/ffi/go/bls"
	"testing"
)
import assert "github.com/stretchr/testify/assert"

func init() {
	bls.Init(bls.BLS12_381)
}
func TestDkg_Set(t *testing.T) {
	assert.True(t, true)
	var dkg Dkg
	ret := dkg.Set(2, 3, GetIDList(0, 3))
	assert.NotNil(t, ret)
	assert.Equal(t, 0, ret.index)
}

func TestNew(t *testing.T) {
	ret := New(7, 13, GetIDList(2, 13))
	assert.NotNil(t, ret)
	assert.Equal(t, 2, ret.index)
}
func TestScalarPK(t *testing.T) {
	var s1, s2 bls.SecretKey
	err := s1.SetDecString("3")
	assert.NoError(t, err)
	err = s2.SetDecString("5")
	assert.NoError(t, err)
	//var p1, p2 bls.SecretKey
	p1 := s1.GetPublicKey()
	assert.NotNil(t, p1)
	p3 := ScalarPK(&s2, p1)
	assert.NotNil(t, p3)
	var s3 bls.SecretKey
	s3.SetDecString("15")
	p3_ := s3.GetPublicKey()
	assert.NotNil(t, p3_)
	assert.True(t, p3.IsEqual(p3_))
}
func TestPkNeg(t *testing.T) {
	var s1, s2 bls.SecretKey
	err := s1.SetDecString("3")
	assert.NoError(t, err)
	err = s2.SetDecString("-3")
	assert.NoError(t, err)
	p1 := s1.GetPublicKey()
	p2 := s2.GetPublicKey()
	p1.Add(p2)
	assert.True(t, p1.IsZero())
	assert.False(t, p2.IsZero())
	p1 = s1.GetPublicKey()
	p1 = PkNeg(p1)
	assert.True(t, p1.IsEqual(p2))
}
func TestSkMul(t *testing.T) {
	var s1, s2, s3 bls.SecretKey
	err := s1.SetDecString("8")
	assert.NoError(t, err)
	err = s2.SetDecString("9")
	assert.NoError(t, err)
	err = s3.SetDecString("72")
	assert.NoError(t, err)
	s3_ := SkMul(&s1, &s2)
	assert.True(t, s3_.IsEqual(&s3))
}
func TestZkProof(t *testing.T) {
	var id bls.ID
	err := id.SetDecString("2")
	assert.NoError(t, err)
	var a0 bls.SecretKey
	err = a0.SetDecString("111")
	assert.NoError(t, err)
	a0G := a0.GetPublicKey()
	proof, err := ZkProof(&id, &a0, a0G)
	assert.NoError(t, err)
	fg, err := ZkVerify(&id, a0G, proof)
	assert.NoError(t, err)
	assert.True(t, fg)
}
func TestZkVerify(t *testing.T) {
	var id bls.ID
	err := id.SetDecString("2000000")
	assert.NoError(t, err)
	var a0 bls.SecretKey
	a0.SetByCSPRNG()
	a0G := a0.GetPublicKey()
	proof, err := ZkProof(&id, &a0, a0G)
	assert.NoError(t, err)
	fg, err := ZkVerify(&id, a0G, proof)
	assert.NoError(t, err)
	assert.True(t, fg)
}
func TestDkg_GenSecretShare(t *testing.T) {
	th, n := 3, 5
	dkgs := make([]Dkg, n)
	for i := 0; i < n; i++ {
		dkgs[i].Set(th, n, GetIDList(i, n))
		assert.Equal(t, n, dkgs[i].n)
		assert.Equal(t, th, dkgs[i].t)
	}
	for i := 0; i < n; i++ {
		shares := dkgs[i].GenSecretShare()
		assert.Equal(t, n, len(shares))
		for j := 0; j < n; j++ {
			fg := VerifySecretShare(&dkgs[j].id, &shares[j], dkgs[i].mpk)
			assert.True(t, fg)
			fmt.Printf("--------- p%+v=>p%+v f%+v(%+v)\n", i, j, i, dkgs[j].id.GetDecString())
			dkgs[j].AddSecretShare(&shares[j])
		}
		fmt.Println()
	}
}

func TestDkgProtocol(t *testing.T) {
	th, n := 3, 5
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
		assert.True(t, dkgs[0].grpPubKey.IsEqual(&dkgs[i].grpPubKey))
	}
	// recover
	S := []int{0, 1, 3, 4}
	ids, sks, pks := genid(S, dkgs)
	var groupSk bls.SecretKey
	err := groupSk.Recover(sks, ids)
	assert.NoError(t, err)
	grpPk := groupSk.GetPublicKey()
	assert.True(t, grpPk.IsEqual(&dkgs[0].grpPubKey))
	var grpPk_ bls.PublicKey
	err = grpPk_.Recover(pks, ids)
	assert.NoError(t, err)
	assert.True(t, grpPk_.IsEqual(&dkgs[0].grpPubKey), "not ok")
}
func genid(set []int, dkgs []Dkg) ([]bls.ID, []bls.SecretKey, []bls.PublicKey) {
	var sks []bls.SecretKey
	var ids []bls.ID
	var pks []bls.PublicKey
	for _, v := range set {
		sks = append(sks, dkgs[v].sigPrivKey)
		ids = append(ids, dkgs[0].ids[v])
		pks = append(pks, *dkgs[v].sigPubKey)
	}
	return ids, sks, pks
}
