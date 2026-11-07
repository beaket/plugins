// The crypto core of plugins/beaket/bin/beaket.mjs, same structure, same wire formats, standard library only.
// A second implementation that proves the format: tools/interop/oracle.mjs cross-checks it with the script.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	b64    = base64.StdEncoding.EncodeToString    // Buffer#toString("base64"): padded, + and /
	b64url = base64.RawURLEncoding.EncodeToString // Buffer#toString("base64url"): no padding, - and _
	salt   = []byte("beaket-team-v2")
)

func fromB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

func random(n int) []byte { b := make([]byte, n); rand.Read(b); return b } // never fails since Go 1.24
func randomID() string    { return b64url(random(16)) }
func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// hkdfKey and hkdfBits are the same function in Go: WebCrypto's deriveKey(AES-GCM, 256) is HKDF to 32 bytes.
func hkdfKey(secret []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, secret, salt, info, 32)
	if err != nil {
		panic(err) // only for keyLength > 255*32
	}
	return k
}

func gcm(key []byte, randomNonce bool) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	var a cipher.AEAD
	if randomNonce {
		a, err = cipher.NewGCMWithRandomNonce(block) // output is nonce(12) || ct || tag(16): the seal blob
	} else {
		a, err = cipher.NewGCM(block)
	}
	if err != nil {
		panic(err)
	}
	return a
}

// seal: base64(nonce || ct || tag).
func seal(key, plain []byte, aad string) string {
	return b64(gcm(key, true).Seal(nil, nil, plain, []byte(aad)))
}

func unsealBytes(key, blob []byte, aad string) ([]byte, error) {
	return gcm(key, true).Open(nil, nil, blob, []byte(aad))
}

func unseal(key []byte, blob, aad string) ([]byte, error) {
	raw, err := fromB64(blob)
	if err != nil {
		return nil, err
	}
	return unsealBytes(key, raw, aad)
}

type pair struct{ PublicKey, PrivateKey string }

// keyPair: raw 32-byte public key, PKCS#8 DER private key, as WebCrypto exports them.
func keyPair() (pair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return pair{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return pair{}, err
	}
	return pair{b64(priv.PublicKey().Bytes()), b64(der)}, nil
}

func importPublic(s string) (*ecdh.PublicKey, error) {
	raw, err := fromB64(s)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(raw)
}

func importPrivate(s string) (*ecdh.PrivateKey, error) {
	der, err := fromB64(s)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(*ecdh.PrivateKey)
	if !ok || priv.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("not an X25519 private key: %T", k)
	}
	return priv, nil
}

// wrap: base64(ephemeralRawPub32 || nonce || ct || tag), key = HKDF(X25519(eph, member), "wrap").
func wrap(teamKey []byte, publicKey, aad string) (string, error) {
	pub, err := importPublic(publicKey)
	if err != nil {
		return "", err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	shared, err := eph.ECDH(pub) // refuses an all-zero result (low-order point), as WebCrypto does
	if err != nil {
		return "", err
	}
	sealed := gcm(hkdfKey(shared, "wrap"), true).Seal(nil, nil, teamKey, []byte(aad))
	return b64(append(eph.PublicKey().Bytes(), sealed...)), nil
}

func unwrap(blob, privateKey, aad string) ([]byte, error) {
	raw, err := fromB64(blob)
	if err != nil {
		return nil, err
	}
	if len(raw) < 32 {
		return nil, errors.New("wrapped key too short")
	}
	eph, err := ecdh.X25519().NewPublicKey(raw[:32])
	if err != nil {
		return nil, err
	}
	priv, err := importPrivate(privateKey)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	return unsealBytes(hkdfKey(shared, "wrap"), raw[32:], aad)
}

func wrapAad(team, member string, epoch int) string {
	return fmt.Sprintf("%s/%s/%d", team, member, epoch)
}
func cardAad(team, member string) string { return team + "/" + member }

// jsonStringify is JSON.stringify for the values this client seals: no HTML escaping, no trailing newline.
// Go still writes U+2028/U+2029 as  /  where JS writes them raw; both parse to the same string.
func jsonStringify(v any) []byte {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

type Card struct {
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

func sealCard(teamKey []byte, team, member string, card Card) string {
	return seal(hkdfKey(teamKey, "members"), jsonStringify(card), cardAad(team, member))
}

func openCard(teamKey []byte, team, member, blob string) (Card, error) {
	var c Card
	plain, err := unseal(hkdfKey(teamKey, "members"), blob, cardAad(team, member))
	if err == nil {
		err = json.Unmarshal(plain, &c)
	}
	return c, err
}

// An invite's secret gives the token Beaket checks by its hash, and the key that seals the team key.
func inviteToken(secret string) (string, error) {
	s, err := fromB64(secret)
	if err != nil {
		return "", err
	}
	return b64url(hkdfKey(s, "invite")), nil
}

func inviteKey(secret string) ([]byte, error) {
	s, err := fromB64(secret)
	if err != nil {
		return nil, err
	}
	return hkdfKey(s, "invite-key"), nil
}

type Record struct {
	ID         string `json:"id"`
	Epoch      int    `json:"epoch"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type Plain struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

func recordAad(team, id string, epoch int) string { return fmt.Sprintf("%s/%s/%d", team, id, epoch) }

func sealRecord(teamKey []byte, team, id string, epoch int, name, text string) Record {
	nonce := random(12)
	ct := gcm(hkdfKey(teamKey, "records"), false).Seal(nil, nonce, jsonStringify(Plain{name, text}), []byte(recordAad(team, id, epoch)))
	return Record{id, epoch, b64(nonce), b64(ct)}
}

func openRecord(teamKey []byte, team string, r Record) (Plain, error) {
	var p Plain
	nonce, err := fromB64(r.Nonce)
	if err != nil {
		return p, err
	}
	ct, err := fromB64(r.Ciphertext)
	if err != nil {
		return p, err
	}
	a := gcm(hkdfKey(teamKey, "records"), false)
	if len(nonce) != a.NonceSize() {
		return p, errors.New("bad nonce length") // cipher.AEAD.Open panics on a wrong-size nonce; WebCrypto would just fail
	}
	plain, err := a.Open(nil, nonce, ct, []byte(recordAad(team, r.ID, r.Epoch)))
	if err == nil {
		err = json.Unmarshal(plain, &p)
	}
	return p, err
}

// uuidV4 is crypto.randomUUID(). (Go 1.27 has package uuid; written out here to keep the floor at Go 1.24.)
func uuidV4() string {
	b := random(16)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
