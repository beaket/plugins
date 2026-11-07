// v3go: Beaket team records protocol v3, draft 2 (PROTOCOL.md), written from the spec.
//
//	v3go make <out.json>   write a scenario file (atomically)
//	v3go check <in.json>   accept the scenario and refuse each must-refuse case
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

type Member struct {
	Member   string   `json:"member"`
	Publics  Bundle   `json:"publics"`
	Privates Privates `json:"privates"`
}
type Invite struct {
	Code      string `json:"code"`
	TokenHash string `json:"tokenHash"`
	Wrapped   string `json:"wrapped"`
}
type Scenario struct {
	Team      string            `json:"team"`
	Member    string            `json:"member"`
	Publics   Bundle            `json:"publics"`
	Privates  Privates          `json:"privates"`
	Other     Member            `json:"other"`
	Epoch     int               `json:"epoch"`
	Wrapped   string            `json:"wrapped"`
	Previous  map[string]string `json:"previous"`
	Invite    Invite            `json:"invite"`
	Cards     map[string]string `json:"cards"`
	Records   []Record          `json:"records"`
	Passports []Passport        `json:"passports"`
}

var expectedRecords = []Body{
	{Name: "2026-11-07-kafka-or-sqs.md", Text: "# SQS로 간다\n\n- Decided by: 플랫폼 리드\n- Why: 운영 부담 🙂\n"},
	{Name: "2026-10-01-old.md", Text: "epoch 1 record <a&b>\n"},
}
var expectedFields = Fields{Label: "3분기 인력 계획", Owner: "테스트 Person", Links: []Link{{Rel: "source", Href: "https://jira.example.invalid/browse/OPS-42"}}}

const meName, otherName = "테스트 Person", "다른 Member"
const decided, reviewBy = "2026-11-07", "2027-01-15"
const server = "https://example.invalid"

func wrapAad(team, member string, epoch int) string {
	return team + "/" + member + "/" + strconv.Itoa(epoch)
}

func makeScenario(out string) error {
	team, me, other := randomID(), randomID(), randomID()
	myPub, myPriv, err := newMember()
	if err != nil {
		return err
	}
	otPub, otPriv, err := newMember()
	if err != nil {
		return err
	}
	k1, k2 := random(32), random(32)
	myEd, err := ed25519Private(myPriv.Ed25519)
	if err != nil {
		return err
	}
	otEd, err := ed25519Private(otPriv.Ed25519)
	if err != nil {
		return err
	}
	secret := random(32)
	code, err := makeInviteCode(server, team, secret)
	if err != nil {
		return err
	}
	wrapped, err := wrap(k2, myPub, wrapAad(team, me, 2))
	if err != nil {
		return err
	}
	myCard, err := sealCard(k2, team, me, Card{meName, myPub})
	if err != nil {
		return err
	}
	otCard, err := sealCard(k2, team, other, Card{otherName, otPub})
	if err != nil {
		return err
	}
	id0, id1 := uuid4(), uuid4()
	r0, err := sealRecord(k2, team, id0, 2, me, myEd, expectedRecords[0])
	if err != nil {
		return err
	}
	r1, err := sealRecord(k1, team, id1, 1, other, otEd, expectedRecords[1])
	if err != nil {
		return err
	}
	rb := reviewBy
	p0, err := sealPassport(k2, team, Passport{ID: id0, Epoch: 2, Author: me, Decided: decided, ReviewBy: &rb}, expectedFields, myEd)
	if err != nil {
		return err
	}
	s := Scenario{
		Team: team, Member: me, Publics: myPub, Privates: myPriv,
		Other:    Member{other, otPub, otPriv},
		Epoch:    2,
		Wrapped:  wrapped,
		Previous: map[string]string{"2": seal(hkdfKey(k2, "previous"), k1, team+"/2")},
		Invite: Invite{
			Code:      code,
			TokenHash: sha256hex([]byte(inviteToken(secret))),
			Wrapped:   seal(inviteKey(secret), k2, team+"/invite"),
		},
		Cards:     map[string]string{me: myCard, other: otCard},
		Records:   []Record{r0, r1},
		Passports: []Passport{p0},
	}
	j, err := jsonBytes(s)
	if err != nil {
		return err
	}
	if err := writeAtomic(out, j); err != nil {
		return err
	}
	fmt.Printf("v3go: wrote %s\n", out)
	return nil
}

// writeAtomic writes to a temporary file in the same directory, syncs it, and renames it over out.
func writeAtomic(out string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(out), "."+filepath.Base(out)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, out)
}

// --- check ---

type state struct {
	s     Scenario
	keys  map[int][]byte
	cards map[string]OpenedCard
	otEd  ed25519.PrivateKey
	myEd  ed25519.PrivateKey
}

var failures int

func ok(format string, a ...any) { fmt.Printf("ok      "+format+"\n", a...) }
func fail(format string, a ...any) {
	failures++
	fmt.Printf("FAIL    "+format+"\n", a...)
}

// refuse reports a must-refuse case: err must be non-nil and contain want.
func refuse(name, what string, err error, want string) {
	switch {
	case err == nil:
		fail("%-4s %s was accepted", name, what)
	case !strings.Contains(err.Error(), want):
		fail("%-4s %s refused for the wrong reason: %v (want %q)", name, what, err, want)
	default:
		fmt.Printf("refused %-4s %s: %v\n", name, what, err)
	}
}

func checkMember(m Member) error {
	if err := checkID("member", m.Member); err != nil {
		return err
	}
	x, err := x25519Private(m.Privates.X25519)
	if err != nil {
		return err
	}
	dk, err := mlkemPrivate(m.Privates.MLKEM)
	if err != nil {
		return err
	}
	e, err := ed25519Private(m.Privates.Ed25519)
	if err != nil {
		return err
	}
	xp, err := decB64("publics x25519", m.Publics.X25519, 32)
	if err != nil {
		return err
	}
	kp, err := decB64("publics mlkem", m.Publics.MLKEM, 1184)
	if err != nil {
		return err
	}
	ep, err := checkEd25519Public(m.Publics.Ed25519)
	if err != nil {
		return err
	}
	if !bytes.Equal(x.PublicKey().Bytes(), xp) || !bytes.Equal(dk.EncapsulationKey().Bytes(), kp) || !bytes.Equal(e.Public().(ed25519.PublicKey), ep) {
		return fmt.Errorf("privates of %s do not match its publics", m.Member)
	}
	return nil
}

func checkScenario(in string) error {
	raw, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var st state
	if err := strictUnmarshal(raw, &st.s); err != nil {
		return fmt.Errorf("scenario JSON: %w", err)
	}
	s := &st.s
	team := s.Team
	if err := checkID("team", team); err != nil {
		return err
	}
	if err := checkEpoch(s.Epoch); err != nil {
		return err
	}
	me := Member{s.Member, s.Publics, s.Privates}
	for _, m := range []Member{me, s.Other} {
		if err := checkMember(m); err != nil {
			return err
		}
	}
	ok("privates (PKCS#8 48 B, seed 64 B, PKCS#8 48 B) are canonical and match publics for both members")
	st.myEd, _ = ed25519Private(s.Privates.Ed25519)
	st.otEd, _ = ed25519Private(s.Other.Privates.Ed25519)

	st.keys = map[int][]byte{}
	k, err := unwrap(s.Wrapped, s.Privates, wrapAad(team, s.Member, s.Epoch))
	if err != nil {
		return err
	}
	st.keys[s.Epoch] = k
	ok("unwrap epoch %d key (1180-byte blob, recipientX derived from the private key)", s.Epoch)

	for key := range s.Previous {
		e, err := strconv.Atoi(key)
		if err != nil || strconv.Itoa(e) != key || e < 2 || e > s.Epoch {
			return fmt.Errorf("previous: bad epoch key %q", key)
		}
	}
	for e := s.Epoch; e >= 2; e-- {
		p, has := s.Previous[strconv.Itoa(e)]
		if !has {
			return fmt.Errorf("previous[%d] missing", e)
		}
		old, err := unseal("previous", hkdfKey(st.keys[e], "previous"), p, team+"/"+strconv.Itoa(e))
		if err != nil {
			return err
		}
		if len(old) != 32 {
			return errors.New("previous key is not 32 bytes")
		}
		st.keys[e-1] = old
		ok("open epoch %d key via previous[%d]", e-1, e)
	}

	secret, err := parseInviteCode(s.Invite.Code, team)
	if err != nil {
		return err
	}
	if sha256hex([]byte(inviteToken(secret))) != s.Invite.TokenHash {
		return errors.New("invite tokenHash mismatch")
	}
	ik, err := unseal("invite", inviteKey(secret), s.Invite.Wrapped, team+"/invite")
	if err != nil {
		return err
	}
	if !bytes.Equal(ik, st.keys[s.Epoch]) {
		return errors.New("invite does not open to the current key")
	}
	ok("invite: bkt3. code for this team, token hash matches, opens the epoch %d key", s.Epoch)

	st.cards = map[string]OpenedCard{}
	for m, blob := range s.Cards {
		c, err := openCard(st.keys[s.Epoch], team, m, blob)
		if err != nil {
			return fmt.Errorf("card %s: %w", m, err)
		}
		st.cards[m] = c
	}
	if c := st.cards[s.Member]; c.Name != meName || c.Keys != s.Publics {
		return fmt.Errorf("my card: %+v", c.Card)
	}
	if c := st.cards[s.Other.Member]; c.Name != otherName || c.Keys != s.Other.Publics {
		return fmt.Errorf("other card: %+v", c.Card)
	}
	ok("both cards open at epoch %d and pass E1: %q, %q", s.Epoch, meName, otherName)

	if len(s.Records) != 2 {
		return fmt.Errorf("%d records, want 2", len(s.Records))
	}
	seen := map[string]bool{}
	for i, r := range s.Records {
		b, err := openRecord(st.keys, team, r, st.cards)
		if err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
		matched := false
		for _, e := range expectedRecords {
			if e == b && !seen[e.Name] {
				seen[e.Name], matched = true, true
			}
		}
		if !matched {
			return fmt.Errorf("record %d plaintext unexpected: %q", i, b.Name)
		}
		ok("record %d (epoch %d, by %s) verified and opened: %s", i, r.Epoch, st.cards[r.Author].Name, b.Name)
	}
	if s.Records[0].Author != s.Member || s.Records[0].Epoch != 2 || s.Records[1].Author != s.Other.Member || s.Records[1].Epoch != 1 {
		return errors.New("records are not record 0 at epoch 2 by member, record 1 at epoch 1 by other")
	}

	if len(s.Passports) != 1 {
		return fmt.Errorf("%d passports, want 1", len(s.Passports))
	}
	p := s.Passports[0]
	f, err := openPassport(st.keys, team, p, st.cards)
	if err != nil {
		return fmt.Errorf("passport: %w", err)
	}
	if !reflect.DeepEqual(f, expectedFields) || p.Decided != decided || p.ReviewBy == nil || *p.ReviewBy != reviewBy || p.ID != s.Records[0].ID || p.Author != s.Member || p.Epoch != 2 {
		return fmt.Errorf("passport fields unexpected: %+v %+v", f, p)
	}
	ok("passport for record 0 verified and opened: %s", f.Label)

	refusals(&st)
	if failures > 0 {
		return fmt.Errorf("%d must-refuse case(s) failed", failures)
	}
	fmt.Printf("PASS v3go check %s (accepted, 13 must-refuse cases refused)\n", in)
	return nil
}

func refusals(st *state) {
	s := &st.s
	team := s.Team
	r0, r1 := s.Records[0], s.Records[1]

	// R1
	t := r0
	t.Author = s.Other.Member
	_, err := openRecord(st.keys, team, t, st.cards)
	refuse("R1", "record author swapped to the other member", err, "bad signature")

	// R2: the signature must verify, then the open fails.
	t, err = signRecord(team, t, st.otEd)
	if err != nil {
		fail("R2 re-sign: %v", err)
	} else {
		signed, _, _, _ := recordSigned(team, t)
		if verifySig(st.cards[t.Author].Ed, signed, t.Sig) != nil {
			fail("R2 re-signed record's signature does not verify")
		}
		_, err = openRecord(st.keys, team, t, st.cards)
		refuse("R2", "record re-signed by the other member (signature verifies)", err, "AES-GCM open failed")
	}

	// W1-W3
	aad := wrapAad(team, s.Member, s.Epoch)
	wb, _ := decB64("wrapped", s.Wrapped, -1)
	flip := func(at int) string { b := append([]byte{}, wb...); b[at] ^= 0x01; return b64(b) }
	_, err = unwrap(flip(32+500), s.Privates, aad)
	refuse("W1", "wrapped with one kemCt byte flipped", err, "AES-GCM open failed")
	_, err = unwrap(flip(3), s.Privates, aad)
	refuse("W2", "wrapped with one ephPub byte flipped", err, "AES-GCM open failed")
	_, err = unwrap(b64(wb[:len(wb)-1]), s.Privates, aad)
	refuse("W3", "wrapped one byte short", err, "want exactly 1180")

	// P1, P2
	p := s.Passports[0]
	moved := "2027-02-15"
	p.ReviewBy = &moved
	_, err = openPassport(st.keys, team, p, st.cards)
	refuse("P1", "passport reviewBy moved, old sig kept", err, "bad signature")
	p, err = signPassport(team, p, st.myEd)
	if err != nil {
		fail("P2 re-sign: %v", err)
	} else {
		signed, _, _ := passportSigned(team, p)
		if verifySig(st.cards[p.Author].Ed, signed, p.Sig) != nil {
			fail("P2 re-signed passport's signature does not verify")
		}
		_, err = openPassport(st.keys, team, p, st.cards)
		refuse("P2", "passport reviewBy moved and re-signed by the member (signature verifies)", err, "AES-GCM open failed")
	}

	// E1a: identity key on the other member's card, record 1 signed (R = identity, S = 0).
	ident, _ := hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000")
	weakSig := append(append([]byte{}, ident...), make([]byte, 32)...)
	forgedR1 := r1
	forgedR1.Sig = b64(weakSig)
	fsigned, _, _, _ := recordSigned(team, forgedR1)
	goAlone := ed25519.Verify(ed25519.PublicKey(ident), fsigned, weakSig)
	refuse("E1a", fmt.Sprintf("other's card with identity ed25519 key (ed25519.Verify alone would accept the forged record 1: %v)", goAlone),
		e1Card(st, ident, forgedR1), "E1: ed25519 public key has small order")

	// E1b: non-canonical y = p + 1.
	pp1, _ := hex.DecodeString("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	refuse("E1b", "other's card with non-canonical y = p+1", e1Card(st, pp1, r1), "E1: ed25519 public key is not canonical")

	// B1-B3
	t = r0
	t.Sig = strings.TrimRight(r0.Sig, "=")
	_, err = openRecord(st.keys, team, t, st.cards)
	refuse("B1", "record sig with '=' padding stripped", err, "not canonical b64")
	t = r0
	t.Nonce = " " + r0.Nonce
	_, err = openRecord(st.keys, team, t, st.cards)
	refuse("B2", "record nonce with a leading space", err, "not canonical b64")
	t = r0
	t.Sig = trailingBitsVariant(r0.Sig)
	if x, _ := base64.StdEncoding.DecodeString(t.Sig); !bytes.Equal(x, mustB64(r0.Sig)) {
		fail("B3 variant should decode to the same bytes under a lenient decoder")
	}
	_, err = openRecord(st.keys, team, t, st.cards)
	refuse("B3", "record sig whose last data character differs only in trailing bits", err, "not canonical b64")

	// I1
	_, err = parseInviteCode("bkt2."+strings.TrimPrefix(s.Invite.Code, "bkt3."), team)
	refuse("I1", "invite code with prefix bkt2.", err, "does not start with bkt3.")
}

// e1Card reseals the other member's card with a given ed25519 key and tries to open it, then the record.
func e1Card(st *state, ed []byte, r Record) error {
	c := Card{otherName, st.s.Other.Publics}
	c.Keys.Ed25519 = b64(ed)
	blob, err := sealCard(st.keys[st.s.Epoch], st.s.Team, st.s.Other.Member, c)
	if err != nil {
		return err
	}
	oc, err := openCard(st.keys[st.s.Epoch], st.s.Team, st.s.Other.Member, blob)
	if err != nil {
		return err
	}
	cards := map[string]OpenedCard{st.s.Member: st.cards[st.s.Member], st.s.Other.Member: oc}
	_, err = openRecord(st.keys, st.s.Team, r, cards)
	return err
}

// trailingBitsVariant changes the last non-padding character so only the unused low bits differ.
func trailingBitsVariant(s string) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	body := strings.TrimRight(s, "=")
	pad := s[len(body):]
	i := strings.IndexByte(alpha, body[len(body)-1])
	return body[:len(body)-1] + string(alpha[i^1]) + pad
}

func main() {
	if len(os.Args) == 5 && os.Args[1] == "variant" {
		if err := makeVariant(os.Args[2], os.Args[3], os.Args[4]); err != nil {
			fmt.Println("variant:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: v3go make|check <file.json>")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "make":
		err = makeScenario(os.Args[2])
	case "check":
		err = checkScenario(os.Args[2])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Printf("REFUSED %s: %v\n", os.Args[2], err)
		os.Exit(1)
	}
}

func mustB64(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }
