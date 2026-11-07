package main

import "testing"

// JSON.stringify leaves <, > and & as they are; Go's encoder escapes them unless told not to.
func TestStringifyMatchesJS(t *testing.T) {
	got := string(jsonStringify(Plain{"a<b>&c", "x"}))
	if got != `{"name":"a<b>&c","text":"x"}` {
		t.Fatal(got)
	}
}

// WebCrypto refuses an all-zero X25519 peer key; so must Go.
func TestLowOrderPoint(t *testing.T) {
	if _, err := wrap(random(32), b64(make([]byte, 32)), "a"); err == nil {
		t.Fatal("zero public key accepted")
	}
}
