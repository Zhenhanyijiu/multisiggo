/*
cd bls
make minimised_static
*/

package main

import (
	"crypto/rand"
	"fmt"
	"github.com/Zhenhanyijiu/frostgo/frost"
	bls "github.com/herumi/bls/ffi/go/bls"
)

type SeqRead struct {
}

func (self *SeqRead) Read(buf []byte) (int, error) {
	n := len(buf)
	for i := 0; i < n; i++ {
		buf[i] = byte(i)
	}
	return n, nil
}

func testReadRand() {
	s1 := new(SeqRead)
	bls.SetRandFunc(s1)
	var sec bls.SecretKey
	sec.SetByCSPRNG()
	buf := sec.GetLittleEndian()
	fmt.Printf("1. buf=%x\n", buf)
	for i := 0; i < len(buf); i++ {
		if buf[i] != byte(i) {
			fmt.Printf("err %d\n", i)
		}
	}
	bls.SetRandFunc(rand.Reader)
	sec.SetByCSPRNG()
	buf = sec.GetLittleEndian()
	fmt.Printf("2. (cr.Read) buf=%x\n", buf)
	bls.SetRandFunc(nil)
	sec.SetByCSPRNG()
	buf = sec.GetLittleEndian()
	fmt.Printf("3. (cr.Read) buf=%x\n", buf)
}

func main1() {
	bls.Init(bls.BLS12_381)
	var sec bls.SecretKey
	sec.SetByCSPRNG()
	fmt.Printf("sec:%s\n", sec.SerializeToHexStr())
	pub := sec.GetPublicKey()
	fmt.Printf("pub:%s\n", pub.SerializeToHexStr())
	msgTbl := []string{"abc", "def", "123"}
	n := len(msgTbl)
	sigVec := make([]*bls.Sign, n)
	for i := 0; i < n; i++ {
		m := msgTbl[i]
		sigVec[i] = sec.Sign(m)
		fmt.Printf("%d. sign(%s)=%s\n", i, m, sigVec[i].SerializeToHexStr())
	}
	agg := sigVec[0]
	for i := 1; i < n; i++ {
		agg.Add(sigVec[i])
	}
	hashPt := bls.HashAndMapToSignature([]byte(msgTbl[0]))
	for i := 1; i < n; i++ {
		hashPt.Add(bls.HashAndMapToSignature([]byte(msgTbl[i])))
	}
	fmt.Printf("verify %t\n", bls.VerifyPairing(agg, hashPt, pub))
	testReadRand()
}

func main() {
	bls.Init(bls.BLS12_381)
	var sec bls.SecretKey
	//sec.SetByCSPRNG()
	sec.SetDecString("3")
	str := sec.GetDecString()
	fmt.Printf("sk dec string:%+v\n", str)
	var fr, fr2, out bls.Fr
	fr.SetString(str, 10)
	fr2.SetString("9", 10)
	bls.FrMul(&out, &fr, &fr2)
	fmt.Printf("fr*fr2:%+v\n", out.GetString(10))
	var sk bls.SecretKey
	sk.SetDecString(out.GetString(10))
	//
	var sk1, sk2 bls.SecretKey
	sk1.SetDecString("2")
	sk2.SetDecString("3")
	out2 := frost.SkMul(&sk1, &sk2)
	if out2 == nil {
		panic("error SkMul")
	}
	fmt.Printf("out2:%+v\n", out2.GetDecString())
	//sk1.Add(&sk2)
	//fmt.Printf("sk2 add :%+v\n", sk1.GetDecString())
	pk1 := sk1.GetPublicKey()
	pk2 := sk2.GetPublicKey()
	fmt.Printf("pk1:%+v\npk2:%+v\n", pk1.GetHexString(), pk2.GetHexString())
	var g1, g2 bls.G2
	g1.SetString(pk1.GetHexString(), 16)
	g2.SetString(pk2.GetHexString(), 16)
	fmt.Printf("g1:%+v\ng2:%+v\n", g1.GetString(16), g2.GetString(16))

}
