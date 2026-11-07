// make/check: the scenario format and assertions of ../oracle.mjs, so each side opens what the other made.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
)

type Invite struct {
	Code      string `json:"code"`
	TokenHash string `json:"tokenHash"`
	Wrapped   string `json:"wrapped"`
}

type Scenario struct {
	Team       string            `json:"team"`
	Member     string            `json:"member"`
	PublicKey  string            `json:"publicKey"`
	PrivateKey string            `json:"privateKey"`
	Epoch      int               `json:"epoch"`
	Wrapped    string            `json:"wrapped"`
	Previous   map[string]string `json:"previous"`
	Invite     Invite            `json:"invite"`
	Card       string            `json:"card"`
	Records    []Record          `json:"records"`
}

var expected = []Plain{
	{"2026-11-07-kafka-or-sqs.md", "# SQS로 간다\n\n- Decided by: 플랫폼 리드\n- Why: 운영 부담 🙂\n"},
	{"2026-10-01-old.md", "epoch 1 record\n"},
}

const cardName = "테스트 Person"

type inviteCode struct {
	Server string `json:"server"`
	Team   string `json:"team"`
	Secret string `json:"secret"`
}

func makeScenario(out string) error {
	team, member := randomID(), randomID()
	p, err := keyPair()
	if err != nil {
		return err
	}
	k1, k2 := random(32), random(32)
	secret := b64(random(32))
	token, err := inviteToken(secret)
	if err != nil {
		return err
	}
	wrapped, err := wrap(k2, p.PublicKey, wrapAad(team, member, 2))
	if err != nil {
		return err
	}
	ik, err := inviteKey(secret)
	if err != nil {
		return err
	}
	v := Scenario{
		Team: team, Member: member, PublicKey: p.PublicKey, PrivateKey: p.PrivateKey, Epoch: 2,
		Wrapped:  wrapped,
		Previous: map[string]string{"2": seal(hkdfKey(k2, "previous"), k1, team+"/2")},
		Invite: Invite{
			Code:      "bkt2." + b64url(jsonStringify(inviteCode{"https://example.invalid", team, secret})),
			TokenHash: sha256hex(token),
			Wrapped:   seal(ik, k2, team+"/invite"),
		},
		Card: sealCard(k2, team, member, Card{cardName, p.PublicKey}),
		Records: []Record{
			sealRecord(k2, team, uuidV4(), 2, expected[0].Name, expected[0].Text),
			sealRecord(k1, team, uuidV4(), 1, expected[1].Name, expected[1].Text),
		},
	}
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	e.SetIndent("", "  ")
	if err := e.Encode(v); err != nil {
		return err
	}
	if err := os.WriteFile(out, bytes.TrimSuffix(buf.Bytes(), []byte("\n")), 0o644); err != nil {
		return err
	}
	fmt.Printf("beaket-go: wrote %s\n", out)
	return nil
}

type failure string

func ok(c bool, m string) {
	if !c {
		panic(failure("FAIL: " + m))
	}
	fmt.Printf("  ok  %s\n", m)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(failure("FAIL: " + err.Error()))
	}
	return v
}

func checkScenario(file string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if f, isF := r.(failure); isF {
				err = errors.New(string(f))
				return
			}
			panic(r)
		}
	}()
	var v Scenario
	if err := json.Unmarshal(must(os.ReadFile(file)), &v); err != nil {
		return err
	}
	k2 := must(unwrap(v.Wrapped, v.PrivateKey, wrapAad(v.Team, v.Member, v.Epoch)))
	ok(len(k2) == 32, "unwrap team key (X25519 pkcs8 private + ephemeral raw public, HKDF wrap, AES-GCM)")
	k1 := must(unseal(hkdfKey(k2, "previous"), v.Previous["2"], v.Team+"/2"))
	ok(len(k1) == 32, "open epoch 1 key from epoch 2 via 'previous'")
	var code inviteCode
	if len(v.Invite.Code) < 5 {
		return errors.New("FAIL: invite code too short")
	}
	must(0, json.Unmarshal(must(base64.RawURLEncoding.DecodeString(v.Invite.Code[5:])), &code))
	ok(code.Team == v.Team, "invite code bkt2. base64url JSON")
	ok(sha256hex(must(inviteToken(code.Secret))) == v.Invite.TokenHash, "invite token = b64url(HKDF bits 'invite'), sha256 hex matches")
	ik := must(unseal(must(inviteKey(code.Secret)), v.Invite.Wrapped, v.Team+"/invite"))
	ok(bytes.Equal(ik, k2), "invite opens the same team key")
	card := must(openCard(k2, v.Team, v.Member, v.Card))
	ok(card.Name == cardName && card.PublicKey == v.PublicKey, "card opens with 'members' key and team/member AAD")
	keys := map[int][]byte{1: k1, 2: k2}
	for i, r := range v.Records {
		got := must(openRecord(keys[r.Epoch], v.Team, r))
		found := false
		for _, e := range expected {
			found = found || (e.Name == got.Name && e.Text == got.Text)
		}
		ok(found, "record "+strconv.Itoa(i)+" (epoch "+strconv.Itoa(r.Epoch)+") opens, UTF-8 text equal")
	}
	swapped := v.Records[0]
	swapped.ID = v.Records[1].ID
	_, e1 := openRecord(k2, v.Team, swapped)
	ok(e1 != nil, "record with swapped id (AAD) is refused")
	_, e2 := unwrap(v.Wrapped, v.PrivateKey, wrapAad(v.Team, v.Member, 1))
	ok(e2 != nil, "wrap with wrong epoch AAD is refused")
	fmt.Printf("beaket-go: %s PASSES\n", file)
	return nil
}
