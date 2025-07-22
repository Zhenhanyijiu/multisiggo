package frost

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"github.com/herumi/bls/ffi/go/bls"
)

type Dkg struct {
	t, n int
	a0   bls.SecretKey
	a0G  *bls.PublicKey
	msk  []bls.SecretKey
	mpk  []bls.PublicKey
	id   bls.ID
}

func (d *Dkg) Set(t, n int) *Dkg {
	d.t = t
	d.n = n
	d.a0.SetByCSPRNG()
	//多项式系数
	d.msk = d.a0.GetMasterSecretKey(t)
	//多项式系数承诺
	d.mpk = bls.GetMasterPublicKey(d.msk)
	//a0对应的公钥
	d.a0G = &d.mpk[0]
	return d
}
func New(t, n int) *Dkg {
	return new(Dkg).Set(t, n)
}

type Poof struct {
	R *bls.PublicKey
	u *bls.SecretKey
}

func (d *Dkg) GenProof() (*Poof, error) {
	return ZkProof(&d.id, &d.a0, d.a0G)
}

//	func PolyCoeffCommitment(coeffs []bls.SecretKey) []bls.PublicKey {
//		return bls.GetMasterPublicKey(coeffs)
//	}
//
// func GenSecretShare(id *bls.ID, coeffs []bls.SecretKey) {
//
// }
func Hash2SecretKey(input []byte) (*bls.SecretKey, error) {
	H := sha256.New()
	H.Write(input)
	ret := H.Sum(nil)
	var s bls.SecretKey
	if err := s.SetLittleEndianMod(ret); err != nil {
		return nil, err
	}
	return &s, nil
}
func GetHashInput(id *bls.ID, a0G, comRi *bls.PublicKey) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.Write(id.Serialize())
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(a0G.Serialize())
	if err != nil {
		return nil, err
	}
	_, err = buf.Write(comRi.Serialize())
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func ZkProof(id *bls.ID, a0 *bls.SecretKey, a0G *bls.PublicKey) (poof *Poof, err error) {
	var k bls.SecretKey
	k.SetByCSPRNG()
	comRi := k.GetPublicKey()
	input, err := GetHashInput(id, a0G, comRi)
	if err != nil {
		return nil, err
	}
	ci, err := Hash2SecretKey(input)
	if err != nil {
		return nil, err
	}
	out := SkMul(a0, ci)
	if out == nil {
		return nil, errors.New("SkMul error")
	}
	out.Add(&k)

	return &Poof{R: comRi, u: out}, nil
}
func ZkVerify(id *bls.ID, a0G *bls.PublicKey, poof *Poof) (bool, error) {
	input, err := GetHashInput(id, a0G, poof.R)
	if err != nil {
		return false, err
	}
	ci, err := Hash2SecretKey(input)
	if err != nil {
		return false, err
	}
	left := poof.u.GetPublicKey()
	// ci*PK
	rignt := ScalarPK(ci, a0G)
	rignt = PkNeg(rignt)
	left.Add(rignt)
	return left.IsEqual(poof.R), nil
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
func tmp() {
	bls.Init(bls.BLS12_381)
	//bls.
	sha256.New()
}
