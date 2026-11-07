// Protocol v3 draft 2 (PROTOCOL.md): primitives, strict encodings, wrap, cards, records, passports, invites.
// Every function returns an error for bad input; nothing here panics on input it is given.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var SALT = []byte("beaket-team-v3")

// --- Rule 4: strict encodings ---

var (
	stdStrict = base64.StdEncoding.Strict()
	urlStrict = base64.RawURLEncoding.Strict()
)

func b64(b []byte) string    { return base64.StdEncoding.EncodeToString(b) }
func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// decB64 decodes standard padded base64 and refuses it unless re-encoding gives the same string.
// want < 0 means any length.
func decB64(what, s string, want int) ([]byte, error) {
	b, err := stdStrict.DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, fmt.Errorf("%s: not canonical b64", what)
	}
	if want >= 0 && len(b) != want {
		return nil, fmt.Errorf("%s: %d bytes, want %d", what, len(b), want)
	}
	return b, nil
}

func decB64url(what, s string) ([]byte, error) {
	b, err := urlStrict.DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, fmt.Errorf("%s: not canonical b64url", what)
	}
	return b, nil
}

var idRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var dateRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

func checkID(what, id string) error {
	if !idRe.MatchString(id) {
		return fmt.Errorf("%s: bad id %q", what, id)
	}
	return nil
}
func checkEpoch(e int) error {
	if e < 1 {
		return fmt.Errorf("bad epoch %d", e)
	}
	return nil
}

// checkDate: the shape YYYY-MM-DD, as the spec words it (a calendar check is not specified; see report).
func checkDate(what, d string) error {
	if !dateRe.MatchString(d) {
		return fmt.Errorf("%s: bad date %q", what, d)
	}
	return nil
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// JSON as JSON.stringify writes it: compact, no HTML escaping.
func jsonBytes(v any) ([]byte, error) {
	return json.Marshal(v, jsontext.EscapeForHTML(false), json.Deterministic(true))
}

// strictUnmarshal: case-sensitive names, no duplicates, no unknown members, valid UTF-8 (json v2 defaults + reject unknown).
func strictUnmarshal(b []byte, v any) error {
	return json.Unmarshal(b, v, json.RejectUnknownMembers(true))
}

// --- Primitives ---

func random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b) // never fails (crypto/rand contract since Go 1.24)
	return b
}
func randomID() string { return b64url(random(16)) }

func uuid4() string {
	b := random(16)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func hkdfBits(ikm []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, ikm, SALT, info, 32)
	if err != nil { // only for keyLength > 255*32
		panic(err)
	}
	return k
}
func hkdfKey(ikm []byte, info string) []byte { return hkdfBits(ikm, info) }

func aead(key []byte) cipher.AEAD {
	blk, _ := aes.NewCipher(key) // key is always 32 bytes from hkdfKey
	a, _ := cipher.NewGCM(blk)
	return a
}

func sealRaw(key, plain []byte, aad string) []byte {
	nonce := random(12)
	return append(nonce, aead(key).Seal(nil, nonce, plain, []byte(aad))...)
}
func seal(key, plain []byte, aad string) string { return b64(sealRaw(key, plain, aad)) }

func unsealRaw(key, blob []byte, aad string) ([]byte, error) {
	if len(blob) < 28 {
		return nil, errors.New("sealed blob shorter than 28 bytes")
	}
	p, err := aead(key).Open(nil, blob[:12], blob[12:], []byte(aad))
	if err != nil {
		return nil, errors.New("AES-GCM open failed")
	}
	return p, nil
}
func unseal(what string, key []byte, blob string, aad string) ([]byte, error) {
	b, err := decB64(what, blob, -1)
	if err != nil {
		return nil, err
	}
	p, err := unsealRaw(key, b, aad)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	return p, nil
}

// --- Keys ---

type Bundle struct {
	X25519  string `json:"x25519"`
	MLKEM   string `json:"mlkem"`
	Ed25519 string `json:"ed25519"`
}

type Privates struct {
	X25519  string `json:"x25519"`
	MLKEM   string `json:"mlkem"`
	Ed25519 string `json:"ed25519"`
}

func newMember() (Bundle, Privates, error) {
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Bundle{}, Privates{}, err
	}
	xp, err := x509.MarshalPKCS8PrivateKey(x)
	if err != nil {
		return Bundle{}, Privates{}, err
	}
	k, err := mlkem.GenerateKey768()
	if err != nil {
		return Bundle{}, Privates{}, err
	}
	epub, epriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Bundle{}, Privates{}, err
	}
	ep, err := x509.MarshalPKCS8PrivateKey(epriv)
	if err != nil {
		return Bundle{}, Privates{}, err
	}
	return Bundle{b64(x.PublicKey().Bytes()), b64(k.EncapsulationKey().Bytes()), b64(epub)},
		Privates{b64(xp), b64(k.Bytes()), b64(ep)}, nil
}

func x25519Private(p string) (*ecdh.PrivateKey, error) {
	b, err := decB64("x25519 private", p, 48)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("x25519 private: %w", err)
	}
	x, ok := k.(*ecdh.PrivateKey)
	if !ok || x.Curve() != ecdh.X25519() {
		return nil, errors.New("x25519 private: not an X25519 PKCS#8 key")
	}
	return x, nil
}

func ed25519Private(p string) (ed25519.PrivateKey, error) {
	b, err := decB64("ed25519 private", p, 48)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("ed25519 private: %w", err)
	}
	e, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("ed25519 private: not an Ed25519 PKCS#8 key")
	}
	return e, nil
}

func mlkemPrivate(p string) (*mlkem.DecapsulationKey768, error) {
	b, err := decB64("mlkem seed", p, 64)
	if err != nil {
		return nil, err
	}
	return mlkem.NewDecapsulationKey768(b)
}

// E1: canonical y < p, and not one of the five small-order y-coordinates (sign bit ignored).
var smallOrderY = func() [][]byte {
	var out [][]byte
	for _, h := range []string{
		"0000000000000000000000000000000000000000000000000000000000000000", // 0
		"0100000000000000000000000000000000000000000000000000000000000000", // 1
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // p-1
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	} {
		b, _ := hex.DecodeString(h)
		out = append(out, b)
	}
	return out
}()

func checkEd25519Public(s string) (ed25519.PublicKey, error) {
	b, err := decB64("ed25519 public", s, 32)
	if err != nil {
		return nil, err
	}
	y := append([]byte{}, b...)
	y[31] &= 0x7f
	// y < p = 2^255-19: compare big-endian
	p := []byte{0x7f}
	for range 30 {
		p = append(p, 0xff)
	}
	p = append(p, 0xed)
	ybe := make([]byte, 32)
	for i := range 32 {
		ybe[i] = y[31-i]
	}
	if bytes.Compare(ybe, p) >= 0 {
		return nil, errors.New("E1: ed25519 public key is not canonical (y >= p)")
	}
	for _, so := range smallOrderY {
		if bytes.Equal(y, so) {
			return nil, errors.New("E1: ed25519 public key has small order")
		}
	}
	return ed25519.PublicKey(b), nil
}

// E2: exact 64-byte signature; crypto/ed25519 refuses S >= L.
func verifySig(pub ed25519.PublicKey, msg []byte, sig string) error {
	s, err := decB64("sig", sig, 64)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, s) {
		return errors.New("bad signature")
	}
	return nil
}

// --- Wrap ---

const wrapLen = 32 + 1088 + 12 + 32 + 16

var zero32 = make([]byte, 32)

func wrap(secret []byte, bundle Bundle, aad string) (string, error) {
	if len(secret) != 32 {
		return "", errors.New("wrap: secret must be 32 bytes")
	}
	xb, err := decB64("bundle x25519", bundle.X25519, 32)
	if err != nil {
		return "", err
	}
	recipX, err := ecdh.X25519().NewPublicKey(xb)
	if err != nil {
		return "", err
	}
	kb, err := decB64("bundle mlkem", bundle.MLKEM, 1184)
	if err != nil {
		return "", err
	}
	ek, err := mlkem.NewEncapsulationKey768(kb)
	if err != nil {
		return "", err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	ssX, err := eph.ECDH(recipX)
	if err != nil || subtle.ConstantTimeCompare(ssX, zero32) == 1 {
		return "", errors.New("wrap: X25519 shared secret is all zero")
	}
	ssK, kemCt := ek.Encapsulate()
	ephPub := eph.PublicKey().Bytes()
	kek := hkdfKey(concat(ssK, ssX, ephPub, xb), "wrap")
	return b64(concat(ephPub, kemCt, sealRaw(kek, secret, aad))), nil
}

func unwrap(blob string, priv Privates, aad string) ([]byte, error) {
	b, err := decB64("wrapped", blob, -1)
	if err != nil {
		return nil, err
	}
	if len(b) != wrapLen {
		return nil, fmt.Errorf("wrapped: %d bytes, want exactly %d", len(b), wrapLen)
	}
	x, err := x25519Private(priv.X25519)
	if err != nil {
		return nil, err
	}
	dk, err := mlkemPrivate(priv.MLKEM)
	if err != nil {
		return nil, err
	}
	ephPub, kemCt, rest := b[:32], b[32:32+1088], b[32+1088:]
	eph, err := ecdh.X25519().NewPublicKey(ephPub)
	if err != nil {
		return nil, err
	}
	ssX, err := x.ECDH(eph)
	if err != nil || subtle.ConstantTimeCompare(ssX, zero32) == 1 {
		return nil, errors.New("unwrap: X25519 shared secret is all zero")
	}
	ssK, err := dk.Decapsulate(kemCt)
	if err != nil {
		return nil, err
	}
	recipX := x.PublicKey().Bytes() // derived, never a stored copy
	p, err := unsealRaw(hkdfKey(concat(ssK, ssX, ephPub, recipX), "wrap"), rest, aad)
	if err != nil {
		return nil, fmt.Errorf("unwrap: %w", err)
	}
	if len(p) != 32 {
		return nil, errors.New("unwrap: team key is not 32 bytes")
	}
	return p, nil
}

// --- Card ---

type Card struct {
	Name string `json:"name"`
	Keys Bundle `json:"keys"`
}

// A card as a reader holds it: checked keys.
type OpenedCard struct {
	Card
	Ed ed25519.PublicKey
}

func sealCard(teamKey []byte, team, member string, c Card) (string, error) {
	j, err := jsonBytes(c)
	if err != nil {
		return "", err
	}
	return seal(hkdfKey(teamKey, "members"), j, team+"/"+member), nil
}

// parseCard checks a card's plaintext: strict JSON, E1 on ed25519, exact lengths on the other keys.
func parseCard(plain []byte) (OpenedCard, error) {
	var c Card
	if err := strictUnmarshal(plain, &c); err != nil {
		return OpenedCard{}, fmt.Errorf("card JSON: %w", err)
	}
	ed, err := checkEd25519Public(c.Keys.Ed25519)
	if err != nil {
		return OpenedCard{}, err
	}
	if _, err := decB64("card x25519", c.Keys.X25519, 32); err != nil {
		return OpenedCard{}, err
	}
	kb, err := decB64("card mlkem", c.Keys.MLKEM, 1184)
	if err != nil {
		return OpenedCard{}, err
	}
	if _, err := mlkem.NewEncapsulationKey768(kb); err != nil {
		return OpenedCard{}, fmt.Errorf("card mlkem: %w", err)
	}
	return OpenedCard{c, ed}, nil
}

func openCard(teamKey []byte, team, member, blob string) (OpenedCard, error) {
	if err := checkID("member", member); err != nil {
		return OpenedCard{}, err
	}
	p, err := unseal("card", hkdfKey(teamKey, "members"), blob, team+"/"+member)
	if err != nil {
		return OpenedCard{}, err
	}
	return parseCard(p)
}

// --- Record ---

type Body struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

type Record struct {
	ID         string `json:"id"`
	Epoch      int    `json:"epoch"`
	Author     string `json:"author"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Sig        string `json:"sig"`
}

func recordAad(team, id string, epoch int, author string) string {
	return team + "/" + id + "/" + strconv.Itoa(epoch) + "/" + author
}

// recordSigned checks the record's encodings, ids and epoch and gives the signed text.
func recordSigned(team string, r Record) ([]byte, []byte, []byte, error) {
	if err := checkID("record id", r.ID); err != nil {
		return nil, nil, nil, err
	}
	if err := checkID("author", r.Author); err != nil {
		return nil, nil, nil, err
	}
	if err := checkEpoch(r.Epoch); err != nil {
		return nil, nil, nil, err
	}
	nonce, err := decB64("nonce", r.Nonce, 12)
	if err != nil {
		return nil, nil, nil, err
	}
	ct, err := decB64("ciphertext", r.Ciphertext, -1)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(ct) < 16 {
		return nil, nil, nil, errors.New("ciphertext shorter than its tag")
	}
	if _, err := decB64("sig", r.Sig, 64); err != nil {
		return nil, nil, nil, err
	}
	s := "beaket-record-v3\n" + team + "\n" + r.ID + "\n" + strconv.Itoa(r.Epoch) + "\n" + r.Author + "\n" + sha256hex(concat(nonce, ct))
	return []byte(s), nonce, ct, nil
}

func sealRecord(teamKey []byte, team, id string, epoch int, author string, ed ed25519.PrivateKey, body Body) (Record, error) {
	j, err := jsonBytes(body)
	if err != nil {
		return Record{}, err
	}
	nonce := random(12)
	ct := aead(hkdfKey(teamKey, "records")).Seal(nil, nonce, j, []byte(recordAad(team, id, epoch, author)))
	r := Record{ID: id, Epoch: epoch, Author: author, Nonce: b64(nonce), Ciphertext: b64(ct), Sig: b64(make([]byte, 64))}
	return signRecord(team, r, ed)
}

func signRecord(team string, r Record, ed ed25519.PrivateKey) (Record, error) {
	r.Sig = b64(make([]byte, 64)) // placeholder so the encoding check passes; sig is not in the signed text
	s, _, _, err := recordSigned(team, r)
	if err != nil {
		return r, err
	}
	r.Sig = b64(ed25519.Sign(ed, s))
	return r, nil
}

// openRecord: encodings/ids/epoch, author's card, E2 signature, then decrypt.
func openRecord(keys map[int][]byte, team string, r Record, cards map[string]OpenedCard) (Body, error) {
	signed, nonce, ct, err := recordSigned(team, r)
	if err != nil {
		return Body{}, err
	}
	c, ok := cards[r.Author]
	if !ok {
		return Body{}, fmt.Errorf("no card for author %s", r.Author)
	}
	if err := verifySig(c.Ed, signed, r.Sig); err != nil {
		return Body{}, err
	}
	k, ok := keys[r.Epoch]
	if !ok {
		return Body{}, fmt.Errorf("no key for epoch %d", r.Epoch)
	}
	p, err := aead(hkdfKey(k, "records")).Open(nil, nonce, ct, []byte(recordAad(team, r.ID, r.Epoch, r.Author)))
	if err != nil {
		return Body{}, errors.New("record: AES-GCM open failed")
	}
	var b Body
	if err := strictUnmarshal(p, &b); err != nil {
		return Body{}, fmt.Errorf("record body JSON: %w", err)
	}
	return b, nil
}

// --- Passport ---

type Link struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}
type Fields struct {
	Label string `json:"label"`
	Owner string `json:"owner"`
	Links []Link `json:"links"`
}
type Passport struct {
	ID       string  `json:"id"`
	Epoch    int     `json:"epoch"`
	Author   string  `json:"author"`
	Decided  string  `json:"decided"`
	ReviewBy *string `json:"reviewBy"`
	Sealed   string  `json:"sealed,omitzero"`
	Sig      string  `json:"sig,omitzero"`
	// present is false when the wire object had no reviewBy member at all (null is not the same as absent).
	present bool
}

// UnmarshalJSON records whether reviewBy was present, then decodes strictly.
func (p *Passport) UnmarshalJSON(b []byte) error {
	type plain Passport
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	var q plain
	if err := strictUnmarshal(b, &q); err != nil {
		return err
	}
	*p = Passport(q)
	_, p.present = raw["reviewBy"]
	return nil
}

func rbText(p Passport) string {
	if p.ReviewBy == nil {
		return ""
	}
	return *p.ReviewBy
}

func checkPassportClear(p Passport) error {
	if !p.present {
		return errors.New("passport: reviewBy member missing (must be a date or null)")
	}
	if err := checkID("passport id", p.ID); err != nil {
		return err
	}
	if err := checkID("author", p.Author); err != nil {
		return err
	}
	if err := checkEpoch(p.Epoch); err != nil {
		return err
	}
	if err := checkDate("decided", p.Decided); err != nil {
		return err
	}
	if p.ReviewBy != nil {
		if err := checkDate("reviewBy", *p.ReviewBy); err != nil {
			return err
		}
	}
	return nil
}

func passportAad(team string, p Passport) string {
	return team + "/" + p.ID + "/" + strconv.Itoa(p.Epoch) + "/" + p.Author + "/" + p.Decided + "/" + rbText(p)
}

func passportSigned(team string, p Passport) ([]byte, []byte, error) {
	if err := checkPassportClear(p); err != nil {
		return nil, nil, err
	}
	sealed, err := decB64("sealed", p.Sealed, -1)
	if err != nil {
		return nil, nil, err
	}
	s := "beaket-passport-v3\n" + team + "\n" + p.ID + "\n" + strconv.Itoa(p.Epoch) + "\n" + p.Author + "\n" + p.Decided + "\n" + rbText(p) + "\n" + sha256hex(sealed)
	return []byte(s), sealed, nil
}

func sealPassport(teamKey []byte, team string, p Passport, f Fields, ed ed25519.PrivateKey) (Passport, error) {
	p.present = true
	if err := checkPassportClear(p); err != nil {
		return p, err
	}
	j, err := jsonBytes(f)
	if err != nil {
		return p, err
	}
	p.Sealed = seal(hkdfKey(teamKey, "passport"), j, passportAad(team, p))
	return signPassport(team, p, ed)
}

func signPassport(team string, p Passport, ed ed25519.PrivateKey) (Passport, error) {
	s, _, err := passportSigned(team, p)
	if err != nil {
		return p, err
	}
	p.Sig = b64(ed25519.Sign(ed, s))
	return p, nil
}

func openPassport(keys map[int][]byte, team string, p Passport, cards map[string]OpenedCard) (Fields, error) {
	signed, sealed, err := passportSigned(team, p)
	if err != nil {
		return Fields{}, err
	}
	c, ok := cards[p.Author]
	if !ok {
		return Fields{}, fmt.Errorf("no card for author %s", p.Author)
	}
	if err := verifySig(c.Ed, signed, p.Sig); err != nil {
		return Fields{}, err
	}
	k, ok := keys[p.Epoch]
	if !ok {
		return Fields{}, fmt.Errorf("no key for epoch %d", p.Epoch)
	}
	plain, err := unsealRaw(hkdfKey(k, "passport"), sealed, passportAad(team, p))
	if err != nil {
		return Fields{}, fmt.Errorf("passport: %w", err)
	}
	var f Fields
	if err := strictUnmarshal(plain, &f); err != nil {
		return Fields{}, fmt.Errorf("passport fields JSON: %w", err)
	}
	return f, nil
}

// --- Invites ---

type InviteCode struct {
	Server string `json:"server"`
	Team   string `json:"team"`
	Secret string `json:"secret"`
}

func inviteToken(secret []byte) string { return b64url(hkdfBits(secret, "invite")) }
func inviteKey(secret []byte) []byte   { return hkdfKey(secret, "invite-key") }

func makeInviteCode(server, team string, secret []byte) (string, error) {
	j, err := jsonBytes(InviteCode{server, team, b64(secret)})
	if err != nil {
		return "", err
	}
	return "bkt3." + b64url(j), nil
}

// parseInviteCode refuses another prefix, a non-canonical payload and a code for another team.
func parseInviteCode(code, team string) ([]byte, error) {
	rest, ok := strings.CutPrefix(code, "bkt3.")
	if !ok {
		return nil, errors.New("invite code does not start with bkt3.")
	}
	j, err := decB64url("invite code", rest)
	if err != nil {
		return nil, err
	}
	var c InviteCode
	if err := strictUnmarshal(j, &c); err != nil {
		return nil, fmt.Errorf("invite code JSON: %w", err)
	}
	if c.Team != team {
		return nil, fmt.Errorf("invite code is for team %q, not %q", c.Team, team)
	}
	return decB64("invite secret", c.Secret, 32)
}
