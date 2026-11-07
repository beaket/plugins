# Beaket team records, protocol v3 (draft 2)

What changes from v2 (ADR-020, plugins/beaket/bin/beaket.mjs):
1. A passport's label, owner and links are sealed with the team key; only dates, state and trail stay clear (decisions/2026-10-31-build-passport-and-map-now.md, Changes 2026-11-07).
2. A team key reaches a member through a hybrid of X25519 and ML-KEM-768, so a record kept today cannot be opened later by breaking X25519 alone.
3. A member signs what they push (record, passport) with Ed25519; another member checks the signature against the key on the author's card, so no member can write as another.
4. Every reader parses strictly: one encoding per value, exact lengths, checked keys. Two implementations must accept and refuse exactly the same inputs.

Draft 2 settles the 14 points the first independent implementation (Go, from draft 1 alone) found open, and adds rules 4, E1 and E2.

## Encodings (rule 4)
- Text is UTF-8. JSON is written as JavaScript's JSON.stringify writes it (no HTML escaping, no added whitespace in anything sealed or signed).
- **b64** is standard base64 with padding; **b64url** is URL-safe base64 without padding.
- A reader decodes a b64 or b64url value and refuses it unless encoding the decoded bytes again gives back the exact same string. This refuses whitespace, characters outside the alphabet, missing or extra padding, and non-zero trailing bits.
- b64 is used for keys, blobs, nonces, ciphertexts, signatures and the invite secret. b64url is used for team and member ids, tokens and the invite code's payload.
- **Ids.** Team, member and record ids match `^[A-Za-z0-9_-]{1,64}$`; a reader refuses others. Team and member ids are b64url of 16 random bytes; record ids are lowercase UUIDv4. With this alphabet, `/` and newline are safe separators in aads and signed texts.
- **Epoch.** An epoch is a JSON integer ≥ 1. In aads, signed texts and the keys of `previous` it is written in decimal without leading zeros.
- **Dates.** `decided` is `YYYY-MM-DD`. `reviewBy` is `YYYY-MM-DD` or JSON null; the empty string is refused.
- **Hex** is lowercase.

## Constants and primitives
- SALT = UTF-8 "beaket-team-v3". Every HKDF in v3 uses it.
- hkdfKey(ikm, info) = HKDF-SHA256(ikm, salt=SALT, info=UTF-8 info, length 32), used as an AES-256-GCM key.
- hkdfBits(ikm, info) is the same 32 bytes, used as bytes.
- seal(key, plain, aad) = b64(nonce(12) || AES-256-GCM(key, nonce, plain, aad=UTF-8 aad)), where the ciphertext includes the 16-byte tag. unseal reverses it and refuses a decoded length below 28.
- A nonce is 12 random bytes per seal. No key seals more than 2^32 messages.

## A member's keys
| Key | Public | Private |
|---|---|---|
| X25519 | raw 32 bytes | PKCS#8, 48 bytes, as WebCrypto exports it |
| ML-KEM-768 | encapsulation key, raw 1184 bytes | the 64-byte seed d‖z (FIPS 203), as WebCrypto "raw-seed" and Go mlkem.NewDecapsulationKey768 take it |
| Ed25519 | raw 32 bytes | PKCS#8, 48 bytes |

- The public bundle is `{"x25519": b64, "mlkem": b64, "ed25519": b64}`, in that key order.
- **E1, Ed25519 public key check.** A reader refuses an ed25519 public key unless all of the following hold:
  - it decodes to exactly 32 bytes;
  - y (the 255 low bits, little-endian) is below p = 2^255 − 19;
  - y is none of the five small-order y-coordinates: 0, 1, p − 1, and the little-endian encodings 26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05 and c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a. These cover all 8 points of order 1, 2, 4 and 8, whatever the sign bit.

  The check applies when a card is opened, before any signature is checked against its key. It is needed because Go's ed25519.Verify accepts (R = identity, S = 0) for any message under the identity key, and Node refuses it.
- **E2, signatures.** Verification follows RFC 8032 and refuses S ≥ L. A signature decodes to exactly 64 bytes.
- **Other keys.** An X25519 public key decodes to exactly 32 bytes. An ML-KEM encapsulation key decodes to exactly 1184 bytes and must pass the FIPS 203 modulus check; both libraries do this check on import.

## Wrap (hybrid)
wrap(secret32, bundle, aad):
1. eph = a fresh X25519 pair; ssX = X25519(eph.private, bundle.x25519). Refuse if ssX is all zero.
2. (ssK, kemCt) = ML-KEM-768.Encapsulate(bundle.mlkem). kemCt is 1088 bytes.
3. ikm = ssK(32) ‖ ssX(32) ‖ ephPub(32) ‖ recipientX(32). This is an X-Wing-style combiner: the X25519 transcript is bound in, and ML-KEM is IND-CCA, so its ciphertext need not be.
4. kek = hkdfKey(ikm, "wrap").
5. blob = b64(ephPub(32) ‖ kemCt(1088) ‖ nonce(12) ‖ ct(32) ‖ tag(16)), 1180 bytes before base64.

unwrap(blob, privates, aad):
- Refuse a decoded blob whose length is not exactly 1180.
- recipientX is the X25519 public key derived from the recipient's own X25519 private key, never a stored copy.
- ssX = X25519(x25519 private, ephPub). Refuse if it is all zero.
- ssK = Decapsulate(seed, kemCt). A tampered kemCt gives a different implicit-rejection key, so the AES-GCM open fails.
- Build the same ikm and open.

The aad for a member's team key is `${team}/${member}/${epoch}`.

## Card (who a member is)
- card = `{"name": string, "keys": bundle}`, in that key order.
- sealCard(teamKey, team, member, card) = seal(hkdfKey(teamKey, "members"), JSON(card), `${team}/${member}`).
- Cards are sealed with the key of the team's current epoch. Each card travels with `cardEpoch`, the epoch whose key sealed it. In the scenario file, every card is at `epoch`.
- On opening a card, a reader applies E1 to `keys.ed25519` and checks that the other two keys have their exact lengths.

## Record (signed)
- body = JSON({"name", "text"}).
- aad = `${team}/${id}/${epoch}/${author}`, where author is the pusher's member id, bound into the ciphertext.
- nonce: 12 fresh bytes. ciphertext = AES-256-GCM(hkdfKey(teamKey[epoch], "records"), nonce, body, aad), including the tag.
- digest = lowercase hex SHA-256 of the decoded bytes nonce(12) ‖ ciphertext.
- signed = "beaket-record-v3\n" + team + "\n" + id + "\n" + epoch + "\n" + author + "\n" + digest.
- sig = b64(Ed25519.sign(author's private key, UTF-8 signed)).
- wire: `{"id", "epoch", "author", "nonce", "ciphertext", "sig"}`.

To open a record, the reader:
1. checks the encodings, the ids and the epoch;
2. finds the author's card, and refuses if there is none;
3. verifies sig with E2 against the card's ed25519 key;
4. decrypts with the aad above, using the key of the record's epoch.

## Passport (sealed fields, signed)
- **Clear fields:** `{"id", "epoch", "author", "decided", "reviewBy"}`.
  - id is its record's id.
  - epoch is the epoch whose key sealed it.
  - author is the member who pushed the passport. That need not be the record's author, since any member may answer or update.
  - state and trail belong to the server and are not signed.
- **Sealed fields:** sealed = seal(hkdfKey(teamKey[epoch], "passport"), JSON({"label", "owner", "links": [{"rel", "href"}]}), `${team}/${id}/${epoch}/${author}/${decided}/${reviewBy ?? ""}`).
  - The clear dates are bound in the aad, so the server cannot move them without the open failing.
  - Because reviewBy is never "", writing null as "" here is unambiguous.
- digest = lowercase hex SHA-256 of the decoded bytes of sealed.
- signed = "beaket-passport-v3\n" + team + "\n" + id + "\n" + epoch + "\n" + author + "\n" + decided + "\n" + (reviewBy ?? "") + "\n" + digest.
- sig = b64(Ed25519.sign(author's private key, UTF-8 signed)).
- wire: the clear fields + `{"sealed", "sig"}`.
- A reader opens a passport in the same order as a record: encodings, then the author's card, then the signature, then the open.

## Invites and the epoch chain (unchanged in shape from v2, with SALT v3)
- secret = 32 random bytes, as b64.
- token = b64url(hkdfBits(secret bytes, "invite")).
- tokenHash = lowercase hex SHA-256 of the UTF-8 token.
- invite.wrapped = seal(hkdfKey(secret bytes, "invite-key"), teamKey[current epoch], `${team}/invite`).
- code = "bkt3." + b64url(UTF-8 JSON {"server", "team", "secret"}). A reader refuses another prefix, and refuses a code whose team differs from the team it joins.
- previous[e] = seal(hkdfKey(teamKey[e], "previous"), teamKey[e−1], `${team}/${e}`) for e ≥ 2.

## Scenario file (for the cross-check)
The fields, in this order:
- team, member, publics, privates (`{"x25519": pkcs8 b64, "mlkem": seed b64, "ed25519": pkcs8 b64}`)
- other: `{member, publics, privates}`, a second member who authors record 1
- epoch: 2
- wrapped: to member at epoch 2
- previous: `{"2": ...}`
- invite: `{code, tokenHash, wrapped}`, where the code's server is "https://example.invalid"
- cards: `{"<member>": blob, "<other>": blob}`, both at epoch 2
- records: record 0 at epoch 2 by member; record 1 at epoch 1 by other
- passports: one passport for record 0, at epoch 2, by member, decided "2026-11-07", reviewBy "2027-01-15"

Expected plaintexts are matched by record name.

check must accept the file and refuse each of these, each shown failing on its own:
- **R1:** the record's author is swapped to the other member. The signature fails.
- **R2:** the author is set to the other member and the record is re-signed with their key. The signature verifies, and the open fails.
- **W1:** one byte of kemCt is flipped. Unwrap fails.
- **W2:** one byte of ephPub is flipped. Unwrap fails.
- **W3:** the blob is one byte short. It is refused for its length.
- **P1:** the passport's reviewBy is moved in the clear and the old sig is kept. The signature fails.
- **P2:** the same move, with the passport re-signed by the member. The signature verifies, and the open fails.
- **E1a:** the other member's card carries the identity key 0100…00 as ed25519, and record 1 is signed (R = identity, S = 0). The card is refused.
- **E1b:** the card carries a non-canonical y = p + 1 (eeff…ff7f). The card is refused.
- **B1:** the record's sig has its "=" padding stripped. Refused as an encoding.
- **B2:** the record's nonce has a leading space. Refused as an encoding.
- **B3:** the last character of the record's sig is changed so that only the trailing bits differ. Refused as an encoding.
- **I1:** the invite code's "bkt3." prefix is changed to "bkt2.". Refused.
