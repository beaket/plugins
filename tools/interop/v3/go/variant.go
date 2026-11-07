package main

// variant: take a valid scenario and write a variant that is still validly sealed and signed,
// differing in one point the spec leaves to the reader. Used to compare Go and JS acceptance.

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"os"
)

func makeVariant(in, kind, out string) error {
	raw, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var s Scenario
	if err := strictUnmarshal(raw, &s); err != nil {
		return err
	}
	team := s.Team
	k2, err := unwrap(s.Wrapped, s.Privates, wrapAad(team, s.Member, s.Epoch))
	if err != nil {
		return err
	}
	k1, err := unseal("previous", hkdfKey(k2, "previous"), s.Previous["2"], team+"/2")
	if err != nil {
		return err
	}
	myEd, _ := ed25519Private(s.Privates.Ed25519)
	otEd, _ := ed25519Private(s.Other.Privates.Ed25519)
	textEdit := func(j []byte) []byte { return j }
	sealOtherCard := func(plain []byte) {
		s.Cards[s.Other.Member] = seal(hkdfKey(k2, "members"), plain, team+"/"+s.Other.Member)
	}
	switch kind {
	case "reviewby-missing":
		p := s.Passports[0]
		p.ReviewBy = nil
		if p, err = sealPassport(k2, team, p, expectedFields, myEd); err != nil {
			return err
		}
		s.Passports[0] = p
		textEdit = func(j []byte) []byte { return bytes.Replace(j, []byte(`"reviewBy":null,`), nil, 1) }
	case "date-feb30":
		p := s.Passports[0]
		p.Decided = "2026-02-30"
		if p, err = sealPassport(k2, team, p, expectedFields, myEd); err != nil {
			return err
		}
		s.Passports[0] = p
	case "card-extra-member":
		j, _ := jsonBytes(Card{otherName, s.Other.Publics})
		sealOtherCard(append(j[:len(j)-1], []byte(`,"x":1}`)...))
	case "card-dup-name":
		j, _ := jsonBytes(Card{otherName, s.Other.Publics})
		sealOtherCard(append([]byte(`{"name":"someone else",`), j[1:]...))
	case "card-mlkem-modulus":
		c := Card{otherName, s.Other.Publics}
		c.Keys.MLKEM = b64(bytes.Repeat([]byte{0xff}, 1184))
		j, _ := jsonBytes(c)
		sealOtherCard(j)
	case "body-extra-member":
		r := s.Records[1]
		j, _ := jsonBytes(expectedRecords[1])
		j = append(j[:len(j)-1], []byte(`,"x":1}`)...)
		nonce := random(12)
		r.Nonce = b64(nonce)
		r.Ciphertext = b64(aead(hkdfKey(k1, "records")).Seal(nil, nonce, j, []byte(recordAad(team, r.ID, r.Epoch, r.Author))))
		if r, err = signRecord(team, r, otEd); err != nil {
			return err
		}
		s.Records[1] = r
	case "body-lone-surrogate-key":
		// a member name that is a lone surrogate: JSON.parse accepts it, json v2 refuses it
		r := s.Records[1]
		j, _ := jsonBytes(expectedRecords[1])
		j = append(j[:len(j)-1], []byte(`,"\ud800":1}`)...)
		nonce := random(12)
		r.Nonce = b64(nonce)
		r.Ciphertext = b64(aead(hkdfKey(k1, "records")).Seal(nil, nonce, j, []byte(recordAad(team, r.ID, r.Epoch, r.Author))))
		if r, err = signRecord(team, r, otEd); err != nil {
			return err
		}
		s.Records[1] = r
	case "epoch-2.0":
		id := s.Records[0].ID
		textEdit = func(j []byte) []byte {
			return bytes.Replace(j, []byte(`"id":"`+id+`","epoch":2,`), []byte(`"id":"`+id+`","epoch":2.0,`), 1)
		}
	case "dup-author":
		id := s.Records[0].ID
		textEdit = func(j []byte) []byte {
			return bytes.Replace(j, []byte(`"id":"`+id+`","epoch":2,`), []byte(`"id":"`+id+`","epoch":2,"author":"`+s.Other.Member+`",`), 1)
		}
	case "record-unknown-member":
		id := s.Records[0].ID
		textEdit = func(j []byte) []byte {
			return bytes.Replace(j, []byte(`"id":"`+id+`",`), []byte(`"id":"`+id+`","ID":"x",`), 1)
		}
	default:
		return fmt.Errorf("unknown variant %q", kind)
	}
	j, err := json.Marshal(s, jsontext.EscapeForHTML(false), json.Deterministic(true))
	if err != nil {
		return err
	}
	e := textEdit(j)
	if textKinds[kind] && bytes.Equal(e, j) {
		return fmt.Errorf("variant %s: text edit did not apply", kind)
	}
	return writeAtomic(out, e)
}

var textKinds = map[string]bool{"reviewby-missing": true, "epoch-2.0": true, "dup-author": true, "record-unknown-member": true}
