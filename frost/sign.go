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
	return &DEList{index: d.index,
		id: d.id, E: E, D: D}
}

type SA struct {
	t, n       int
	deLists    []*DEList
	grpPubKey  *bls.PublicKey  //todo:
	sigPubkeys []bls.PublicKey //todo:
}

func (s *SA) Set(t, n int, grpPubKey *bls.PublicKey, sigPubkeys []bls.PublicKey) *SA {
	s.t = t
	s.n = n
	s.deLists = make([]*DEList, n)
	s.sigPubkeys = sigPubkeys
	s.grpPubKey = grpPubKey
	return s
}
func NewSA(t, n int, grpPubKey *bls.PublicKey, sigPubkeys []bls.PublicKey) *SA {
	return new(SA).Set(t, n, grpPubKey, sigPubkeys)
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

func IsValid(R, Y *bls.PublicKey, u, c *bls.SecretKey) bool {
	left := u.GetPublicKey()
	right := ScalarPK(c, Y)
	right.Add(R)
	return left.IsEqual(right)
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
	fmt.Printf("sa  chall:%+v\n", challenge.GetDecString())
	for _, sign := range ziList {
		lambda := LagrangeCoefficient(sign.index, ss)
		fmt.Printf("zi %+v,lambda:%+v\n", sign.index, lambda.GetDecString())
		lambda = SkMul(lambda, challenge)
		ok := IsValid(RiList[sign.index], &s.sigPubkeys[sign.index], sign.z, lambda)
		if !ok {
			return nil, fmt.Errorf("not valid")
		}
	}
	fmt.Printf("---------------------------------------- 1\n")
	var z bls.SecretKey
	for _, sign := range ziList {
		z.Add(sign.z)
	}
	fmt.Printf("---------------------------------------- 2\n")

	//chack
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
		//pk := ScalarPK(rho, dict[ss.indexSet[i]].E)
		//pk.Add(dict[ss.indexSet[i]].D)
		comRi := Ri(dict[index].D, dict[index].E, rho)
		CRi[index] = comRi
		grpComR.Add(comRi)
	}
	c := H2(ss.m, &grpComR, &d.grpPubKey)
	fmt.Printf("dkg chall:%+v\n", c.GetDecString())
	myRho := H1(&d.id, ssBytes)
	zi := SkMul(myRho, &d.e[ss.signCounter-1]) //从0开始
	zi.Add(&d.d[ss.signCounter-1])
	lambda := LagrangeCoefficient(d.index, ss)
	fmt.Printf("dkg %+v,lambda:%+v\n", d.index, lambda.GetDecString())
	out := SkMul(&d.sigPrivKey, lambda)
	out = SkMul(out, c)
	zi.Add(out)
	///////////////
	c2 := SkMul(c, lambda)
	fg := IsValid(CRi[d.index], d.sigPubKey, zi, c2)
	if fg {
		fmt.Printf("====== ooooooooooooooooook\n")
	} else {
		panic("=====  errrrrrrrrrrrrr\nr")
	}
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
func SAVerify(ss *SignerSet) {

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
