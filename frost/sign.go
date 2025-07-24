package frost

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/herumi/bls/ffi/go/bls"
)

type DEList struct {
	index int
	id    bls.ID
	E, D  []bls.PublicKey
}

func (d *Dkg) Preprocess(sigMax int) *DEList {
	d.e = make([]bls.SecretKey, sigMax)
	d.d = make([]bls.SecretKey, sigMax)
	E := make([]bls.PublicKey, sigMax)
	D := make([]bls.PublicKey, sigMax)
	for i := 0; i < sigMax; i++ {
		d.e[i].SetByCSPRNG()
		d.d[i].SetByCSPRNG()
		E[i] = *d.e[i].GetPublicKey()
		D[i] = *d.d[i].GetPublicKey()
	}
	return &DEList{index: d.index,
		id: d.id, E: E, D: D}
}

type SA struct {
	t, n       int
	deLists    []*DEList
	grpPubKey  *bls.PublicKey  //todo:
	sigPubkeys []bls.PublicKey //todo:
}

func (s *SA) Set(t int, ids []bls.ID, Commitments [][]bls.PublicKey) *SA {
	s.t = t
	s.n = len(ids)
	s.deLists = make([]*DEList, s.n)
	s.sigPubkeys = CalSigPubKeys(-1, ids, Commitments)
	s.grpPubKey = CalGrpPubKey(Commitments)
	return s
}
func NewSA(t int, ids []bls.ID, Commitments [][]bls.PublicKey) *SA {
	return new(SA).Set(t, ids, Commitments)
}
func (s *SA) SaveDElist(index int, deList *DEList) {
	s.deLists[index] = deList
}

// t<=alpha<=n
func (s *SA) CreateSignerSet(m string, signCounter int, indexSet []int) *SignerSet {
	alpha := len(indexSet)
	if alpha < s.t || alpha > s.n {
		fmt.Printf("error")
		return nil
	}
	var ret = SignerSet{
		m: m, signCounter: signCounter,
		indexSet: indexSet,
		dEUsing:  map[int]*iDDE{},
	}
	for _, index := range indexSet {
		deLst := s.deLists[index]
		ret.dEUsing[index] = &iDDE{id: &deLst.id,
			D: &deLst.D[signCounter-1], E: &deLst.E[signCounter-1]}
	}
	return &ret
}

type Sign struct {
	index int
	R     *bls.PublicKey
	z     *bls.SecretKey
}

func (s *SA) SignAgg(ss *SignerSet, ziList []*Sign) (*Sign, error) {
	mBbyte := ss.GetBytes()
	var grpComR bls.PublicKey
	RiList := make(map[int]*bls.PublicKey)
	for _, index := range ss.indexSet {
		rho := H1(ss.dEUsing[index].id, mBbyte)
		Ri_ := Ri(ss.dEUsing[index].D, ss.dEUsing[index].E, rho)
		grpComR.Add(Ri_)
		RiList[index] = Ri_
	}
	challenge := H2(ss.m, &grpComR, s.grpPubKey)
	//fmt.Printf("sa  chall:%+v\n", challenge.GetDecString())
	for _, sign := range ziList {
		lambda := LagrangeCoefficient(sign.index, ss)
		//fmt.Printf("zi %+v,lambda:%+v\n", sign.index, lambda.GetDecString())
		lambda = SkMul(lambda, challenge)
		ok := IsValid(RiList[sign.index], &s.sigPubkeys[sign.index], sign.z, lambda)
		if !ok {
			return nil, fmt.Errorf("not valid")
		}
	}
	var z bls.SecretKey
	for _, sign := range ziList {
		z.Add(sign.z)
	}
	return &Sign{index: -1, R: &grpComR, z: &z}, nil
}

type iDDE struct {
	id   *bls.ID
	D, E *bls.PublicKey
}
type SignerSet struct {
	m           string
	signCounter int
	indexSet    []int
	dEUsing     map[int]*iDDE
}

// todo:
func (d *Dkg) Check(setSign []int, ss *SignerSet, dElist []*DEList) {

}

func (ss *SignerSet) GetBytes() []byte {
	var buf bytes.Buffer
	buf.WriteString(ss.m)
	for _, index := range ss.indexSet {
		buf.Write(ss.dEUsing[index].id.GetLittleEndian())
		buf.Write(ss.dEUsing[index].D.Serialize())
		buf.Write(ss.dEUsing[index].E.Serialize())
	}
	return buf.Bytes()
}
func H1(id *bls.ID, ssBytes []byte) *bls.SecretKey {
	h1 := sha256.New()
	h1.Write(ssBytes)
	h1.Write(id.GetLittleEndian())
	ret := h1.Sum(nil)
	var pho bls.SecretKey
	pho.SetLittleEndianMod(ret)
	return &pho
}
func H2(m string, grpR *bls.PublicKey, grpPk *bls.PublicKey) *bls.SecretKey {
	h2 := sha256.New()
	h2.Write([]byte(m))
	h2.Write(grpR.Serialize())
	h2.Write(grpPk.Serialize())
	ret := h2.Sum(nil)
	var c bls.SecretKey
	c.SetLittleEndianMod(ret)
	return &c
}
func Ri(D, E *bls.PublicKey, rho *bls.SecretKey) *bls.PublicKey {
	pk := ScalarPK(rho, E)
	pk.Add(D)
	return pk
}
func (d *Dkg) Sign(ss *SignerSet) *Sign {
	var grpComR bls.PublicKey
	ssBytes := ss.GetBytes()
	dict := ss.dEUsing
	CRi := map[int]*bls.PublicKey{}
	for _, index := range ss.indexSet {
		rho := H1(dict[index].id, ssBytes)
		comRi := Ri(dict[index].D, dict[index].E, rho)
		CRi[index] = comRi
		grpComR.Add(comRi)
	}
	c := H2(ss.m, &grpComR, d.grpPubKey)
	myRho := H1(&d.id, ssBytes)
	zi := SkMul(myRho, &d.e[ss.signCounter-1]) //从0开始
	zi.Add(&d.d[ss.signCounter-1])
	lambda := LagrangeCoefficient(d.index, ss)
	out := SkMul(&d.sigPrivKey, lambda)
	out = SkMul(out, c)
	zi.Add(out)
	return &Sign{index: d.index, R: nil, z: zi}
}

func LagrangeCoefficient(index int, ss *SignerSet) *bls.SecretKey {
	myid := ss.dEUsing[index].id
	var a1, a2, myidfr bls.Fr
	a1.SetInt64(1)
	a2.SetInt64(1)
	myidfr.SetString(myid.GetDecString(), 10)
	for _, ndx := range ss.indexSet {
		if ndx != index {
			idstr := ss.dEUsing[ndx].id.GetDecString()
			var idfr bls.Fr
			idfr.SetString(idstr, 10)
			bls.FrMul(&a1, &a1, &idfr)
			bls.FrSub(&idfr, &idfr, &myidfr)
			bls.FrMul(&a2, &a2, &idfr)
		}
	}
	bls.FrDiv(&a1, &a1, &a2)
	var lambda bls.SecretKey
	lambda.SetDecString(a1.GetString(10))
	return &lambda
}
func VerifyAgg(m string, grpPubKey *bls.PublicKey, sign *Sign) bool {
	c := H2(m, sign.R, grpPubKey)
	return IsValid(sign.R, grpPubKey, sign.z, c)

}
