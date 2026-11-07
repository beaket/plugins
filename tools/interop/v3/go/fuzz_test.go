package main

import (
	"encoding/base64"
	"os"
	"testing"
)

func FuzzStrictB64(f *testing.F) {
	for _, s := range []string{"", "AQ==", "AR==", "AQ", " AQ==", "AQ==\n", "A\nQ==", "////", "-_8=", "AQ=", "AQ==="} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		b, err := decB64("x", s, -1)
		if err == nil && base64.StdEncoding.EncodeToString(b) != s {
			t.Fatalf("accepted non-canonical %q", s)
		}
		// an independent oracle: canonical iff some byte string encodes to s
		lenient, lerr := base64.StdEncoding.DecodeString(s)
		if lerr == nil && base64.StdEncoding.EncodeToString(lenient) == s && err != nil {
			t.Fatalf("refused canonical %q: %v", s, err)
		}
		u, err := decB64url("x", s)
		if err == nil && base64.RawURLEncoding.EncodeToString(u) != s {
			t.Fatalf("accepted non-canonical b64url %q", s)
		}
	})
}

// fixture: a scenario made once, opened, so the record/passport fuzzers have real keys and cards.
var fx struct {
	st   state
	rec  []byte
	pass []byte
	card []byte
}

func fixture(t testing.TB) {
	if fx.st.keys != nil {
		return
	}
	dir := t.TempDir()
	if err := makeScenario(dir + "/s.json"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(dir + "/s.json")
	if err := strictUnmarshal(raw, &fx.st.s); err != nil {
		t.Fatal(err)
	}
	s := &fx.st.s
	k2, err := unwrap(s.Wrapped, s.Privates, wrapAad(s.Team, s.Member, 2))
	if err != nil {
		t.Fatal(err)
	}
	k1, _ := unseal("p", hkdfKey(k2, "previous"), s.Previous["2"], s.Team+"/2")
	fx.st.keys = map[int][]byte{1: k1, 2: k2}
	fx.st.cards = map[string]OpenedCard{}
	for m, b := range s.Cards {
		c, err := openCard(k2, s.Team, m, b)
		if err != nil {
			t.Fatal(err)
		}
		fx.st.cards[m] = c
	}
	fx.rec, _ = jsonBytes(s.Records[0])
	fx.pass, _ = jsonBytes(s.Passports[0])
	fx.card, _ = jsonBytes(Card{meName, s.Publics})
}

func FuzzParseCard(f *testing.F) {
	fixture(f)
	f.Add(fx.card)
	f.Add([]byte(`{"name":"a","keys":{"x25519":"","mlkem":"","ed25519":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		parseCard(b) // must not panic
	})
}

func FuzzOpenRecord(f *testing.F) {
	fixture(f)
	f.Add(fx.rec)
	f.Fuzz(func(t *testing.T, b []byte) {
		var r Record
		if strictUnmarshal(b, &r) != nil {
			return
		}
		body, err := openRecord(fx.st.keys, fx.st.s.Team, r, fx.st.cards)
		if err == nil && body != expectedRecords[0] {
			t.Fatalf("opened to something else: %+v", body)
		}
	})
}

func FuzzOpenPassport(f *testing.F) {
	fixture(f)
	f.Add(fx.pass)
	f.Fuzz(func(t *testing.T, b []byte) {
		var p Passport
		if strictUnmarshal(b, &p) != nil {
			return
		}
		openPassport(fx.st.keys, fx.st.s.Team, p, fx.st.cards)
	})
}

func FuzzInviteCode(f *testing.F) {
	fixture(f)
	f.Add(fx.st.s.Invite.Code)
	f.Add("bkt3.")
	f.Fuzz(func(t *testing.T, code string) {
		parseInviteCode(code, fx.st.s.Team)
	})
}

func FuzzUnwrap(f *testing.F) {
	fixture(f)
	f.Add(fx.st.s.Wrapped)
	f.Fuzz(func(t *testing.T, blob string) {
		k, err := unwrap(blob, fx.st.s.Privates, wrapAad(fx.st.s.Team, fx.st.s.Member, 2))
		if err == nil && blob != fx.st.s.Wrapped && len(k) == 32 {
			t.Logf("a different blob unwrapped (possible only with the same ciphertext)")
		}
	})
}
