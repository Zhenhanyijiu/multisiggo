package frost

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/herumi/bls/ffi/go/bls"
	"strconv"
)

type DEList struct {
	index int
	id    bls.ID
	E, D  []bls.PublicKey
}

func (d *Dkg) Preprocess(n int) *DEList {
	d.e = make([]bls.SecretKey, n)
	d.d = make([]bls.SecretKey, n)
	E := make([]bls.PublicKey, n)
	D := make([]bls.PublicKey, n)
	for i := 0; i < n; i++ {
		d.e[i].SetByCSPRNG()
		d.d[i].SetByCSPRNG()
		E[i] = *d.e[i].GetPublicKey()
		D[i] = *d.d[i].GetPublicKey()
	}
	return &DEList{index: d.index, E: E, D: D}
}

type SA struct {
	t, n    int
	deLists []*DEList
}

func (s *SA) Set(t, n int) *SA {
	s.t = t
	s.n = n
	s.deLists = make([]*DEList, n)
	return s
}
func NewSA(t, n int) *SA {
	return new(SA).Set(t, n)
}
func (s *SA) SaveDElist(index int, deList *DEList) {
	s.deLists[index] = deList
}

// t<=alpha<=n
func (s *SA) CreateSignSet(m string, signCounter int, indexSet []int) *SignerSet {
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
			D: &deLst.D[signCounter], E: &deLst.E[signCounter]}
	}
	return &ret
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
	for i := 0; i < len(ss.indexSet); i++ {
		buf.Write(ss.dEUsing[ss.indexSet[i]].id.GetLittleEndian())
		buf.Write(ss.dEUsing[ss.indexSet[i]].D.Serialize())
		buf.Write(ss.dEUsing[ss.indexSet[i]].E.Serialize())
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
	ret := h2.Sum(grpPk.Serialize())
	var c bls.SecretKey
	c.SetLittleEndianMod(ret)
	return &c
}

func (d *Dkg) Sign(ss *SignerSet) (*bls.PublicKey, *bls.SecretKey) {
	var grpComR bls.PublicKey
	ssBytes := ss.GetBytes()
	dict := ss.dEUsing
	for i := 0; i < len(ss.indexSet); i++ {
		pho := H1(dict[ss.indexSet[i]].id, ssBytes)
		pk := ScalarPK(pho, dict[ss.indexSet[i]].E)
		pk.Add(dict[ss.indexSet[i]].D)
		grpComR.Add(pk)
	}
	c := H2(ss.m, &grpComR, &d.grpPubKey)
	myPho := H1(&d.id, ssBytes)
	z := SkMul(myPho, &d.e[ss.signCounter])
	z.Add(&d.d[ss.signCounter])
	lambda := LagrangeCoefficient(d.index, ss)
	out := SkMul(&d.signPrivKey, lambda)
	out = SkMul(out, c)
	z.Add(out)
	return &grpComR, z
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
func TtestFrLagrangeInterpolation() {
	var out, x1, x2, x3, y1, y2, y3 bls.Fr
	x1.SetString("1", 10)
	x2.SetString("2", 10)
	x3.SetString("3", 10)
	y1.SetString("4", 10)
	y2.SetString("8", 10)
	y3.SetString("14", 10)
	bls.FrLagrangeInterpolation(&out, []bls.Fr{x1, x2, x3}, []bls.Fr{y1, y2, y3})
	fmt.Printf("f(0):%+v\n", out.GetString(10))
	//
	ids := make([]bls.ID, 4)
	for i := 0; i < 4; i++ {
		ids[i].SetDecString(strconv.Itoa(1 + i))
		fmt.Printf("== i:%+v\n", ids[i].GetDecString())
	}
	signer := SignerSet{
		indexSet: []int{0, 1, 2, 3},
		dEUsing:  map[int]*iDDE{},
		//deShare:  map[int]*idDE{0: &idDE{id: &ids[0]}, 1: &idDE{id: &ids[1]}, 2: &idDE{id: &ids[2]}},
	}
	for _, index := range signer.indexSet {
		signer.dEUsing[index] = &iDDE{id: &ids[index]}
	}
	lambda := LagrangeCoefficient(0, &signer)
	fmt.Printf("lambda:%+v\n", lambda.GetDecString())

	var xx, xx2, out2 bls.Fr
	//|G2|=52435875175126190479447740508185965837690552500527637822603658699938581184513
	//     52435875175126190479447740508185965837690552500527637822603658699938581184512
	xx.SetString("52435875175126190479447740508185965837690552500527637822603658699938581184510", 10)
	xx2.SetInt64(3)
	out2.SetInt64(77)
	fmt.Printf("out2:%+v\n", out2.GetString(10))
	bls.FrAdd(&out2, &xx, &xx2)
	fmt.Printf("out2:%+v\n", out2.GetString(10))

}
