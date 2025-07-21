package frost

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"github.com/herumi/bls/ffi/go/bls"
)

func GenPolyCoefficient(threshold int) []bls.SecretKey {
	coeffs_ai := make([]bls.SecretKey, threshold)
	for i := 0; i < threshold; i++ {
		coeffs_ai[i].SetByCSPRNG()
	}
	return coeffs_ai
}
func Hash2SecretKey(input []byte) (error, *bls.SecretKey) {
	var s bls.SecretKey
	if err := s.SetLittleEndianMod(input); err != nil {
		return err, nil
	}
	return nil, &s
}
func GetHashInput(id *bls.ID, pkConstTerm, comRi *bls.PublicKey) (error, []byte) {
	var buf bytes.Buffer
	_, err := buf.Write(id.Serialize())
	if err != nil {
		return err, nil
	}
	_, err = buf.Write(pkConstTerm.Serialize())
	if err != nil {
		return err, nil
	}
	_, err = buf.Write(comRi.Serialize())
	if err != nil {
		return err, nil
	}
	return nil, buf.Bytes()
}
func ZkProof(id *bls.ID, ai0 *bls.SecretKey) (err error, comRi *bls.PublicKey, ui *bls.SecretKey) {
	var k bls.SecretKey
	k.SetByCSPRNG()
	comRi = k.GetPublicKey()
	pkConstTerm := ai0.GetPublicKey()
	err, input := GetHashInput(id, pkConstTerm, comRi)
	if err != nil {
		return err, nil, nil
	}
	err, ci := Hash2SecretKey(input)
	if err != nil {
		return err, nil, nil
	}
	out := SkMul(ai0, ci)
	if out == nil {
		return errors.New("SkMul error"), nil, nil
	}
	out.Add(&k)

	return nil, comRi, out
}
func ZkVerify(id *bls.ID, pkConstTerm *bls.PublicKey, comRi *bls.PublicKey, ui *bls.SecretKey) (error, bool) {
	err, input := GetHashInput(id, pkConstTerm, comRi)
	if err != nil {
		return err, false
	}
	err, _ = Hash2SecretKey(input)
	if err != nil {
		return err, false
	}
	//left := ui.GetPublicKey()
	//rignt := ci.GetPublicKey()
	//bls.SetDstG2()
	return nil, false
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

// func PkNeg(pk *bls.PublicKey) *bls.PublicKey {
//
// }
func tmp() {
	bls.Init(bls.BLS12_381)
	//bls.
	sha256.New()
}
