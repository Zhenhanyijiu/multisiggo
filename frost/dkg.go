package frost

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/herumi/bls/ffi/go/bls"
	"strconv"
)

type IDList struct {
	index int
	ids   []bls.ID
}

func GetIDList(index, n int) *IDList {
	ids := make([]bls.ID, n)
	for i := 0; i < n; i++ {
		ids[i].SetDecString(strconv.Itoa(1 + i))
	}
	ret := &IDList{index: index, ids: ids}
	fmt.Printf("------ index:%+v\n", ret.index)
	for i := 0; i < n; i++ {
		fmt.Printf("ids[%+v]:%+v\n", i, ret.ids[i].GetDecString())
	}
	return ret
}

type Dkg struct {
	t, n        int
	a0          bls.SecretKey
	a0G         *bls.PublicKey
	msk         []bls.SecretKey
	mpk         []bls.PublicKey
	id          bls.ID
	ids         []bls.ID
	index       int
	selfShare   *bls.SecretKey
	sigPrivKey  bls.SecretKey
	sigPubKey   *bls.PublicKey
	Commitments [][]bls.PublicKey //n个承诺向量
	sigPubKeys  []bls.PublicKey
	grpPubKey   *bls.PublicKey
	e, d        []bls.SecretKey //最多签名次数
}

func (d *Dkg) Set(t, n int, idlist *IDList) *Dkg {
	d.t = t
	d.n = n
	d.a0.SetByCSPRNG()
	//多项式系数
	d.msk = d.a0.GetMasterSecretKey(t)
	//多项式系数承诺
	d.mpk = bls.GetMasterPublicKey(d.msk)
	//a0对应的公钥
	d.a0G = &d.mpk[0]
	d.index = idlist.index
	d.ids = idlist.ids
	d.id = d.ids[d.index]
	d.Commitments = make([][]bls.PublicKey, d.n)
	d.Commitments[d.index] = d.mpk
	return d
}
func NewDKG(t, n int, idlist *IDList) *Dkg {
	return new(Dkg).Set(t, n, idlist)
}

type Poof struct {
	R *bls.PublicKey
	u *bls.SecretKey
}

func (d *Dkg) GenProof() (*Poof, error) {
	return ZkProof(&d.id, &d.a0, d.a0G)
}
func (d *Dkg) SaveCommitment(fromIndex int, fromMpk []bls.PublicKey) {
	d.Commitments[fromIndex] = fromMpk
}

func (d *Dkg) GenSecretShare() []bls.SecretKey {
	// f(id1,id2,id3...)
	shares := make([]bls.SecretKey, d.n)
	for i := 0; i < d.n; i++ {
		shares[i].Set(d.msk, &d.ids[i])
	}
	d.selfShare = &shares[d.index]
	return shares
}

func VerifySecretShare(fromId *bls.ID, fromShare *bls.SecretKey, fromMpk []bls.PublicKey) bool {
	pk := fromShare.GetPublicKey()
	var pkCheck bls.PublicKey
	pkCheck.Set(fromMpk, fromId)
	return pk.IsEqual(&pkCheck)
}

func (d *Dkg) AddSecretShare(fromShare *bls.SecretKey) {
	d.sigPrivKey.Add(fromShare)
}

// 计算(calculate)所有其他节点的验证公钥，自己的不计算
func CalSigPubKeys(selfNdx int, ids []bls.ID, Commitments [][]bls.PublicKey) []bls.PublicKey {
	//计算所有其他参与者的验证公钥,
	n := len(ids)
	sigPubKeys := make([]bls.PublicKey, n)
	for i := 0; i < n; i++ {
		//计算 Pi 的验证公钥,自己的无需再计算
		if i != selfNdx {
			for j := 0; j < n; j++ {
				var tmp bls.PublicKey
				tmp.Set(Commitments[j], &ids[i])
				sigPubKeys[i].Add(&tmp)
			}
		}
	}
	return sigPubKeys
}
func (d *Dkg) GenSignKey() {
	d.sigPrivKey.Add(d.selfShare)
	d.sigPubKey = d.sigPrivKey.GetPublicKey()
	//计算所有参与者的验证公钥
	//for i := 0; i < d.n; i++ {
	//	//计算 Pi 的验证公钥,自己的无需再计算
	//	if i != d.index {
	//		for j := 0; j < d.n; j++ {
	//			var tmp bls.PublicKey
	//			tmp.Set(d.Commitments[j], &d.ids[i])
	//			d.sigPubKeys[i].Add(&tmp)
	//		}
	//	}
	//}
	d.sigPubKeys = CalSigPubKeys(d.index, d.ids, d.Commitments)
	d.sigPubKeys[d.index] = *d.sigPubKey
	//	阈值组验证公钥
	d.grpPubKey = CalGrpPubKey(d.Commitments)
}
func CalGrpPubKey(Commitments [][]bls.PublicKey) *bls.PublicKey {
	n := len(Commitments)
	var grpPubKey bls.PublicKey
	for i := 0; i < n; i++ {
		grpPubKey.Add(&Commitments[i][0])
	}
	return &grpPubKey
}
func Hash2SecretKey(id *bls.ID, a0G, comRi *bls.PublicKey) *bls.SecretKey {
	H := sha256.New()
	H.Write(id.Serialize())
	H.Write(a0G.Serialize())
	H.Write(comRi.Serialize())
	ret := H.Sum(nil)
	var s bls.SecretKey
	if err := s.SetLittleEndianMod(ret); err != nil {
		return nil
	}
	return &s
}

func ZkProof(id *bls.ID, a0 *bls.SecretKey, a0G *bls.PublicKey) (poof *Poof, err error) {
	var k bls.SecretKey
	k.SetByCSPRNG()
	comRi := k.GetPublicKey()
	ci := Hash2SecretKey(id, a0G, comRi)
	if ci == nil {
		return nil, fmt.Errorf("ci is nil")
	}
	out := SkMul(a0, ci)
	if out == nil {
		return nil, errors.New("SkMul error")
	}
	out.Add(&k)

	return &Poof{R: comRi, u: out}, nil
}
func ZkVerify(id *bls.ID, a0G *bls.PublicKey, prf *Poof) (bool, error) {
	ci := Hash2SecretKey(id, a0G, prf.R)
	if ci == nil {
		return false, fmt.Errorf("ci si nil")
	}
	//left := poof.u.GetPublicKey()
	//// ci*PK
	//rignt := ScalarPK(ci, a0G)
	//rignt = PkNeg(rignt)
	//left.Add(rignt)
	//return left.IsEqual(poof.R), nil
	fg := IsValid(prf.R, a0G, prf.u, ci)
	if fg {
		return fg, nil

	}

	return false, fmt.Errorf("ZkVerify error")
}
func SkMul(sk1, sk2 *bls.SecretKey) (out *bls.SecretKey) {
	var fr1, fr2 bls.Fr
	fr1.SetString(sk1.GetDecString(), 10)
	fr2.SetString(sk2.GetDecString(), 10)
	bls.FrMul(&fr2, &fr1, &fr2)
	var res bls.SecretKey
	err := res.SetDecString(fr2.GetString(10))
	if err != nil {
		return nil
	}
	return &res
}

func PkNeg(pk *bls.PublicKey) *bls.PublicKey {
	var g bls.G2
	g.SetString(pk.GetHexString(), 16)
	bls.G2Neg(&g, &g)
	pk.SetHexString(g.GetString(16))
	return pk
}
func ScalarPK(sk *bls.SecretKey, pk *bls.PublicKey) *bls.PublicKey {
	var g, tmp bls.G2
	var fr bls.Fr
	g.SetString(pk.GetHexString(), 16)
	fr.SetString(sk.GetHexString(), 16)
	bls.G2Mul(&tmp, &g, &fr)
	var ret bls.PublicKey
	ret.SetHexString(tmp.GetString(16))
	return &ret
}
func IsValid(R, Y *bls.PublicKey, u, c *bls.SecretKey) bool {
	left := u.GetPublicKey()
	right := ScalarPK(c, Y)
	right.Add(R)
	return left.IsEqual(right)
}
