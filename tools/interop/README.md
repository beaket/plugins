# interop: second implementations that check the client's formats

Nothing here ships. The plugin's client is `plugins/beaket/bin/beaket.mjs`. This folder holds the independent implementations and tests used to check its crypto formats and to design the next ones. They are kept on the `v3-prototype` branch for beaket/beaket#3148. The plugin's client moves from JS to Go when protocol v3 is built, as recorded in `decisions/2026-11-07-go-client-with-v3.md` in beaket/beaket.

## The current format (v2)
- `oracle.mjs` reads the crypto core out of `plugins/beaket/bin/beaket.mjs` on every run. It does not copy it. It can:
  - make a team scenario: a member's key pair, the wrapped team key, the previous epoch's key, an invite, a card, records at two epochs;
  - check one;
  - cross-check another implementation: `node tools/interop/oracle.mjs cross <binary> [rounds]`.
- `go/` is the same crypto core in Go, using only the standard library.
- `.github/workflows/interop.yml` runs gofmt, vet, the tests and 20 cross-check rounds each way.
  - Changing one HKDF label in the script made it fail (`cipher: message authentication failed`).
  - It is not on `main`. The v2 format will not change, because v3 replaces it with no migration.

## Protocol v3 (draft 2)
`v3/PROTOCOL.md` is the draft. It has:
- passport label, owner and links sealed;
- a hybrid X25519 + ML-KEM-768 key wrap;
- Ed25519-signed records and passports;
- strict reading:
  - canonical base64;
  - ids, epochs and dates checked;
  - an Ed25519 key check: canonical encoding, none of the five small-order y values.

There are two implementations, each written from the draft alone:
- `v3/v3.mjs` (Node 24+ WebCrypto). Run `node v3/v3.mjs make <file>` and `node v3/v3.mjs check <file>`.
- `v3/go/` (Go 1.27, standard library and encoding/json/v2), with fuzzers in `fuzz_test.go`. Run `go build -o v3go . && ./v3go make|check <file>`.

Status on 2026-11-07:
- 25 cross-check rounds each way pass.
- 13 must-refuse cases are refused on both sides, each for its own reason.
- Six fuzzers ran 30 s each with no crash.

Left for draft 3. `v3/testdata/variants/` holds the files that show each of these.
- JSON is not yet read the same way. Seven validly sealed and signed variants are refused by Go and accepted by JS:
  - a duplicate member;
  - an unknown member;
  - an epoch written `2.0`;
  - a lone surrogate in a member name.

  Proposed rule: every JSON object is parsed and re-serialized in its fixed member order, and must equal the input byte for byte.
- The ML-KEM key's modulus check when a card is opened. The draft is inconsistent about it, and JS checks only the length.
- B3's wording means the last character before the padding.
- The epoch's upper bound (1 to 2^53−1), whether a date must be a real calendar day, and limits on a card's name.

`v3/probe/` and `v3/jsonprobe/` are the small programs that found the Go/Node differences:
- Go's `ed25519.Verify` accepts (R = identity, S = 0) under the identity key for any message, and Node refuses it.
- Go's default base64 decodes `AR==` like `AQ==`.
- Go's and JS's JSON parsers disagree as listed above.

## Notes
`notes/go-hardening.md` is research on hardening a Go client: the pinned hash, reproducible builds, the Ed25519 checks, canonical parsing, fuzzing, network lockdown, provenance, key storage and audits. Each claim is marked as checked against a source, checked by a local experiment, or inferred.
