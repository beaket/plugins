package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
)

func main() {
	out := map[string]any{}
	// ML-KEM: Go key, seed, ek, ct, flipped ct, Go's decap of good and flipped.
	dk, _ := mlkem.GenerateKey768()
	ss, ct := dk.EncapsulationKey().Encapsulate()
	bad := append([]byte{}, ct...)
	bad[500] ^= 1
	ssGood, _ := dk.Decapsulate(ct)
	ssBad, errBad := dk.Decapsulate(bad)
	fmt.Println("go mlkem: decap good == encap ss:", hex.EncodeToString(ss) == hex.EncodeToString(ssGood), "; flipped ct err:", errBad, "; flipped ss differs:", hex.EncodeToString(ssBad) != hex.EncodeToString(ss))
	out["seed"] = hex.EncodeToString(dk.Bytes())
	out["ek"] = hex.EncodeToString(dk.EncapsulationKey().Bytes())
	out["ct"] = hex.EncodeToString(ct)
	out["ctBad"] = hex.EncodeToString(bad)
	out["ssGood"] = hex.EncodeToString(ssGood)
	out["ssBad"] = hex.EncodeToString(ssBad)
	// Short / long seeds
	for _, n := range []int{32, 63, 65, 2400} {
		_, err := mlkem.NewDecapsulationKey768(make([]byte, n))
		fmt.Printf("go mlkem: NewDecapsulationKey768(%d bytes) err=%v\n", n, err)
	}
	_, err := mlkem.NewEncapsulationKey768(make([]byte, 1183))
	fmt.Println("go mlkem: 1183-byte ek err:", err)
	if b, err := hex.DecodeString(os.Getenv("NODE_SEED")); err == nil && len(b) == 64 {
		k, err := mlkem.NewDecapsulationKey768(b)
		fmt.Println("go mlkem: Node seed accepted:", err == nil, "; ek matches Node raw-public:", err == nil && hex.EncodeToString(k.EncapsulationKey().Bytes()) == os.Getenv("NODE_EK"))
	}

	// X25519 low-order points
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	low := map[string]string{
		"zero": "0000000000000000000000000000000000000000000000000000000000000000",
		"one":  "0100000000000000000000000000000000000000000000000000000000000000",
		"ord8": "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
		"p-1":  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	}
	for name, h := range low {
		b, _ := hex.DecodeString(h)
		pub, err := ecdh.X25519().NewPublicKey(b)
		if err != nil {
			fmt.Printf("go x25519 %s: NewPublicKey err=%v\n", name, err)
			continue
		}
		s, err := priv.ECDH(pub)
		fmt.Printf("go x25519 %s: ECDH err=%v shared=%x\n", name, err, s)
	}
	px, _ := priv.Bytes(), 0
	out["x25519priv"] = hex.EncodeToString(px)

	// Ed25519: valid sig, S+L, small-order key with (R=identity, S=0)
	pub, sk, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("beaket-record-v3\nmalleability")
	sig := ed25519.Sign(sk, msg)
	L, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	sLE := sig[32:]
	sBE := make([]byte, 32)
	for i := range sBE {
		sBE[i] = sLE[31-i]
	}
	S := new(big.Int).SetBytes(sBE)
	S.Add(S, L)
	sp := S.FillBytes(make([]byte, 32))
	mal := append([]byte{}, sig[:32]...)
	for i := 31; i >= 0; i-- {
		mal = append(mal, sp[i])
	}
	fmt.Println("go ed25519: valid sig verifies:", ed25519.Verify(pub, msg, sig), "; S+L sig verifies:", ed25519.Verify(pub, msg, mal))
	ident, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	weak := append(append([]byte{}, ident...), make([]byte, 32)...)
	fmt.Println("go ed25519: identity public key, sig (R=identity,S=0) on any message verifies:", ed25519.Verify(ident, msg, weak))
	out["edPub"] = hex.EncodeToString(pub)
	out["msg"] = hex.EncodeToString(msg)
	out["sig"] = hex.EncodeToString(sig)
	out["sigMal"] = hex.EncodeToString(mal)
	out["identPub"] = hex.EncodeToString(ident)
	out["weakSig"] = hex.EncodeToString(weak)
	j, _ := json.Marshal(out)
	os.WriteFile("probe.json", j, 0o600)
}
