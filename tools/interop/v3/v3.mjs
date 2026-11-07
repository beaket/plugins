// Protocol v3 reference, draft 2 (PROTOCOL.md): hybrid X25519 + ML-KEM-768 wrap, Ed25519-signed records and
// passports, sealed passport fields, strict parsing (rule 4, E1, E2). Node 24+ WebCrypto only, no dependencies.
//   node v3.mjs make <out.json> | check <in.json>
import { webcrypto as crypto, createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const { subtle } = crypto;
const enc = new TextEncoder();
const dec = new TextDecoder();
const SALT = enc.encode("beaket-team-v3");
const KEM = { name: "ML-KEM-768" };
const WRAP_LENGTH = 32 + 1088 + 12 + 32 + 16;

// --- Encodings (rule 4): one string per value; a reader refuses any other
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
function strict(s, kind) {
  if (typeof s !== "string") throw new Error(`not a ${kind} string`);
  const bytes = Buffer.from(s, kind);
  if (bytes.toString(kind) !== s) throw new Error(`not canonical ${kind}: ${s.slice(0, 16)}…`);
  return new Uint8Array(bytes);
}
const fromB64 = (s, length) => {
  const bytes = strict(s, "base64");
  if (length !== undefined && bytes.length !== length) throw new Error(`expected ${length} bytes, got ${bytes.length}`);
  return bytes;
};
const fromB64url = (s) => strict(s, "base64url");
const ID = /^[A-Za-z0-9_-]{1,64}$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const id = (s) => {
  if (typeof s !== "string" || !ID.test(s)) throw new Error(`bad id ${s}`);
  return s;
};
const epochOf = (e) => {
  if (!Number.isSafeInteger(e) || e < 1) throw new Error(`bad epoch ${e}`);
  return e;
};
const day = (s, nullable) => {
  if (nullable && s === null) return s;
  if (typeof s !== "string" || !DAY.test(s)) throw new Error(`bad date ${s}`);
  return s;
};

const random = (n) => crypto.getRandomValues(new Uint8Array(n));
const randomId = () => b64url(random(16));
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const cat = (...parts) => new Uint8Array(Buffer.concat(parts.map((p) => Buffer.from(p))));

async function hkdfKey(bytes, info) {
  const base = await subtle.importKey("raw", bytes, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: SALT, info: enc.encode(info) }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function hkdfBits(bytes, info) {
  const base = await subtle.importKey("raw", bytes, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: SALT, info: enc.encode(info) }, base, 256));
}
async function sealBytes(key, plain, aad) {
  const nonce = random(12);
  return cat(nonce, new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: enc.encode(aad) }, key, plain)));
}
const seal = async (key, plain, aad) => b64(await sealBytes(key, plain, aad));
async function unsealBytes(key, bytes, aad) {
  if (bytes.length < 28) throw new Error("sealed blob too short");
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12), additionalData: enc.encode(aad) }, key, bytes.slice(12)));
}
const unseal = (key, blob, aad) => unsealBytes(key, fromB64(blob), aad);

// --- E1: an Ed25519 public key is canonical and not of small order
const P = 2n ** 255n - 19n;
const leInt = (bytes) => BigInt("0x" + Buffer.from(bytes).reverse().toString("hex"));
const SMALL_Y = [0n, 1n, P - 1n, leInt(Buffer.from("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "hex")), leInt(Buffer.from("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "hex"))];
function checkEd25519(s) {
  const bytes = fromB64(s, 32);
  const y = leInt(bytes) & ((1n << 255n) - 1n);
  if (y >= P) throw new Error("ed25519 key not canonical");
  if (SMALL_Y.includes(y)) throw new Error("ed25519 key of small order");
  return s;
}

function checkBundle(keys) {
  checkEd25519(keys.ed25519);
  fromB64(keys.x25519, 32);
  fromB64(keys.mlkem, 1184);
  return keys;
}

// --- A member's keys: X25519 (pkcs8), ML-KEM-768 (64-byte seed), Ed25519 (pkcs8)
async function memberKeys() {
  const x = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const k = await subtle.generateKey(KEM, true, ["encapsulateBits", "decapsulateBits"]);
  const s = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const raw = async (f, key) => b64(new Uint8Array(await subtle.exportKey(f, key)));
  return {
    publics: { x25519: await raw("raw", x.publicKey), mlkem: await raw("raw-public", k.publicKey), ed25519: await raw("raw", s.publicKey) },
    privates: { x25519: await raw("pkcs8", x.privateKey), mlkem: await raw("raw-seed", k.privateKey), ed25519: await raw("pkcs8", s.privateKey) },
  };
}

async function x25519(privateKey, publicRaw) {
  const pub = await subtle.importKey("raw", publicRaw, { name: "X25519" }, false, []);
  const ss = new Uint8Array(await subtle.deriveBits({ name: "X25519", public: pub }, privateKey, 256));
  if (ss.every((b) => b === 0)) throw new Error("X25519 shared secret is all zero");
  return ss;
}

// --- Hybrid wrap: ephPub(32) || kemCt(1088) || nonce || ct || tag
async function wrap(secret, publics, aad) {
  const recipientX = fromB64(publics.x25519, 32);
  const eph = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const ephPub = new Uint8Array(await subtle.exportKey("raw", eph.publicKey));
  const ssX = await x25519(eph.privateKey, recipientX);
  const kemPub = await subtle.importKey("raw-public", fromB64(publics.mlkem, 1184), KEM, false, ["encapsulateBits"]);
  const { sharedKey, ciphertext } = await subtle.encapsulateBits(KEM, kemPub);
  const kek = await hkdfKey(cat(new Uint8Array(sharedKey), ssX, ephPub, recipientX), "wrap");
  return b64(cat(ephPub, new Uint8Array(ciphertext), await sealBytes(kek, secret, aad)));
}

async function unwrap(blob, privates, aad) {
  const bytes = fromB64(blob, WRAP_LENGTH);
  const ephPub = bytes.slice(0, 32);
  const kemCt = bytes.slice(32, 32 + 1088);
  // The recipient's own public key, from its private key, never a stored copy.
  const xPriv = await subtle.importKey("pkcs8", fromB64(privates.x25519, 48), { name: "X25519" }, true, ["deriveBits"]);
  const recipientX = fromB64url((await subtle.exportKey("jwk", xPriv)).x);
  const ssX = await x25519(xPriv, ephPub);
  const kemPriv = await subtle.importKey("raw-seed", fromB64(privates.mlkem, 64), KEM, false, ["decapsulateBits"]);
  const ssK = new Uint8Array(await subtle.decapsulateBits(KEM, kemPriv, kemCt));
  const kek = await hkdfKey(cat(ssK, ssX, ephPub, recipientX), "wrap");
  return unsealBytes(kek, bytes.slice(32 + 1088), aad);
}

// --- Signatures (E2)
const sign = async (privates, text) => {
  const key = await subtle.importKey("pkcs8", fromB64(privates.ed25519, 48), { name: "Ed25519" }, false, ["sign"]);
  return b64(new Uint8Array(await subtle.sign({ name: "Ed25519" }, key, enc.encode(text))));
};
async function verify(publics, text, sig) {
  const key = await subtle.importKey("raw", fromB64(checkEd25519(publics.ed25519), 32), { name: "Ed25519" }, false, ["verify"]);
  if (!(await subtle.verify({ name: "Ed25519" }, key, fromB64(sig, 64), enc.encode(text)))) throw new Error("bad signature");
}

const wrapAad = (team, member, epoch) => `${id(team)}/${id(member)}/${epochOf(epoch)}`;
const sealCard = async (teamKey, team, member, card) => seal(await hkdfKey(teamKey, "members"), enc.encode(JSON.stringify(card)), `${team}/${member}`);
async function openCard(teamKey, team, member, blob) {
  const card = JSON.parse(dec.decode(await unseal(await hkdfKey(teamKey, "members"), blob, `${id(team)}/${id(member)}`)));
  checkBundle(card.keys);
  return card;
}
const inviteToken = async (secret) => b64url(await hkdfBits(fromB64(secret, 32), "invite"));
const inviteKey = (secret) => hkdfKey(fromB64(secret, 32), "invite-key");
function readCode(code, team) {
  if (typeof code !== "string" || !code.startsWith("bkt3.")) throw new Error("not a bkt3. invite code");
  const parsed = JSON.parse(dec.decode(fromB64url(code.slice(5))));
  if (parsed.team !== team) throw new Error("invite code names another team");
  return parsed;
}

// --- Records: author bound in the aad, signature over nonce || ciphertext
const recordAad = (team, r) => `${id(team)}/${id(r.id)}/${epochOf(r.epoch)}/${id(r.author)}`;
const recordSigned = (team, r) => `beaket-record-v3\n${team}\n${r.id}\n${r.epoch}\n${r.author}\n${sha256(cat(fromB64(r.nonce, 12), fromB64(r.ciphertext)))}`;

async function sealRecord(teamKey, team, rid, epoch, author, privates, file) {
  const nonce = random(12);
  const r = { id: rid, epoch, author };
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: enc.encode(recordAad(team, r)) }, await hkdfKey(teamKey, "records"), enc.encode(JSON.stringify(file))));
  const out = { ...r, nonce: b64(nonce), ciphertext: b64(ct) };
  return { ...out, sig: await sign(privates, recordSigned(team, out)) };
}

async function openRecord(keys, team, cards, r) {
  const aad = recordAad(team, r);
  const card = cards[r.author];
  if (!card) throw new Error(`no card for author ${r.author}`);
  await verify(card.keys, recordSigned(team, r), r.sig);
  const plain = await subtle.decrypt({ name: "AES-GCM", iv: fromB64(r.nonce, 12), additionalData: enc.encode(aad) }, await hkdfKey(keys[r.epoch], "records"), fromB64(r.ciphertext));
  return JSON.parse(dec.decode(plain));
}

// --- Passports: dates clear and bound in the aad; label, owner, links sealed
const passportAad = (team, p) => `${id(team)}/${id(p.id)}/${epochOf(p.epoch)}/${id(p.author)}/${day(p.decided)}/${day(p.reviewBy, true) ?? ""}`;
const passportSigned = (team, p) => `beaket-passport-v3\n${team}\n${p.id}\n${p.epoch}\n${p.author}\n${p.decided}\n${p.reviewBy ?? ""}\n${sha256(fromB64(p.sealed))}`;

async function sealPassport(teamKey, team, clear, privates, fields) {
  const sealed = await seal(await hkdfKey(teamKey, "passport"), enc.encode(JSON.stringify(fields)), passportAad(team, clear));
  const p = { ...clear, sealed };
  return { ...p, sig: await sign(privates, passportSigned(team, p)) };
}

async function openPassport(keys, team, cards, p) {
  const aad = passportAad(team, p);
  const card = cards[p.author];
  if (!card) throw new Error(`no card for author ${p.author}`);
  await verify(card.keys, passportSigned(team, p), p.sig);
  return JSON.parse(dec.decode(await unseal(await hkdfKey(keys[p.epoch], "passport"), p.sealed, aad)));
}

// --- Scenario
const EXPECTED = [
  { name: "2026-11-07-kafka-or-sqs.md", text: "# SQS로 간다\n\n- Decided by: 플랫폼 리드\n- Why: 운영 부담 🙂\n" },
  { name: "2026-10-01-old.md", text: "epoch 1 record <a&b>\n" },
];
const FIELDS = { label: "3분기 인력 계획", owner: "테스트 Person", links: [{ rel: "source", href: "https://jira.example.invalid/browse/OPS-42" }] };
const NAMES = { me: "테스트 Person", other: "다른 Member" };

async function make(out) {
  const team = randomId();
  const me = { member: randomId(), ...(await memberKeys()) };
  const other = { member: randomId(), ...(await memberKeys()) };
  const k1 = random(32);
  const k2 = random(32);
  const secret = b64(random(32));
  const v = {
    team,
    member: me.member,
    publics: me.publics,
    privates: me.privates,
    other,
    epoch: 2,
    wrapped: await wrap(k2, me.publics, wrapAad(team, me.member, 2)),
    previous: { 2: await seal(await hkdfKey(k2, "previous"), k1, `${team}/2`) },
    invite: {
      code: "bkt3." + b64url(enc.encode(JSON.stringify({ server: "https://example.invalid", team, secret }))),
      tokenHash: sha256(await inviteToken(secret)),
      wrapped: await seal(await inviteKey(secret), k2, `${team}/invite`),
    },
    cards: {
      [me.member]: await sealCard(k2, team, me.member, { name: NAMES.me, keys: me.publics }),
      [other.member]: await sealCard(k2, team, other.member, { name: NAMES.other, keys: other.publics }),
    },
    records: [
      await sealRecord(k2, team, crypto.randomUUID(), 2, me.member, me.privates, EXPECTED[0]),
      await sealRecord(k1, team, crypto.randomUUID(), 1, other.member, other.privates, EXPECTED[1]),
    ],
  };
  v.passports = [await sealPassport(k2, team, { id: v.records[0].id, epoch: 2, author: me.member, decided: "2026-11-07", reviewBy: "2027-01-15" }, me.privates, FIELDS)];
  writeFileSync(out, JSON.stringify(v, null, 2));
  console.log(`v3(js): wrote ${out}`);
}

const ok = (c, m) => {
  if (!c) throw new Error(`FAIL: ${m}`);
  console.log(`  ok  ${m}`);
};
// Must fail, and (when given) with a message matching `why`, so that each case is shown failing on its own.
async function refused(name, f, why) {
  try {
    await f();
  } catch (error) {
    if (why && !why.test(error.message)) throw new Error(`FAIL: ${name} refused for the wrong reason: ${error.message}`);
    console.log(`  ok  ${name} refused (${error.message})`);
    return;
  }
  throw new Error(`FAIL: ${name} was accepted`);
}
const flip = (blob, at) => {
  const b = fromB64(blob);
  b[at] ^= 1;
  return b64(b);
};

async function check(file) {
  const v = JSON.parse(readFileSync(file, "utf8"));
  const k2 = await unwrap(v.wrapped, v.privates, wrapAad(v.team, v.member, v.epoch));
  ok(k2.length === 32, "hybrid unwrap (X25519 + ML-KEM-768) of the team key, 1180-byte blob");
  const k1 = await unseal(await hkdfKey(k2, "previous"), v.previous[2], `${v.team}/2`);
  ok(k1.length === 32, "epoch 1 key from epoch 2 via 'previous'");
  const { secret } = readCode(v.invite.code, v.team);
  ok(sha256(enc.encode(await inviteToken(secret))) === v.invite.tokenHash, "invite code (bkt3., this team) and token hash");
  ok(Buffer.compare(Buffer.from(await unseal(await inviteKey(secret), v.invite.wrapped, `${v.team}/invite`)), Buffer.from(k2)) === 0, "invite opens the team key");
  const cards = {};
  for (const [member, blob] of Object.entries(v.cards)) cards[member] = await openCard(k2, v.team, member, blob);
  ok(cards[v.member].name === NAMES.me && cards[v.member].keys.ed25519 === v.publics.ed25519, "my card opens, its keys checked (E1)");
  ok(cards[v.other.member].name === NAMES.other && cards[v.other.member].keys.mlkem === v.other.publics.mlkem, "the other member's card opens, its keys checked (E1)");
  const keys = { 1: k1, 2: k2 };
  for (const [i, r] of v.records.entries()) {
    const got = await openRecord(keys, v.team, cards, r);
    const want = EXPECTED.find((e) => e.name === got.name);
    ok(want && want.text === got.text, `record ${i} (epoch ${r.epoch}, by ${r.author === v.member ? "me" : "other"}) verifies and opens`);
  }
  const p = await openPassport(keys, v.team, cards, v.passports[0]);
  ok(p.label === FIELDS.label && p.owner === FIELDS.owner && p.links[0].href === FIELDS.links[0].href, "passport verifies and its sealed label, owner and links open");

  const r0 = v.records[0];
  const p0 = v.passports[0];
  const aadOf = wrapAad(v.team, v.member, v.epoch);
  await refused("R1 record with author swapped", () => openRecord(keys, v.team, cards, { ...r0, author: v.other.member }), /signature/);
  const r2 = { ...r0, author: v.other.member };
  r2.sig = await sign(v.other.privates, recordSigned(v.team, r2));
  await refused("R2 record re-signed by another member", () => openRecord(keys, v.team, cards, r2), /operation|decrypt|tag/i);
  await refused("W1 wrap with a kemCt bit flipped", () => unwrap(flip(v.wrapped, 40), v.privates, aadOf), /operation|decrypt|tag/i);
  await refused("W2 wrap with an ephPub bit flipped", () => unwrap(flip(v.wrapped, 3), v.privates, aadOf));
  await refused("W3 wrap one byte short", () => unwrap(b64(fromB64(v.wrapped).slice(0, WRAP_LENGTH - 1)), v.privates, aadOf), /expected 1180 bytes/);
  await refused("P1 passport with its review date moved", () => openPassport(keys, v.team, cards, { ...p0, reviewBy: "2099-01-01" }), /signature/);
  const p2 = { ...p0, reviewBy: "2099-01-01" };
  p2.sig = await sign(v.privates, passportSigned(v.team, p2));
  await refused("P2 passport moved and re-signed", () => openPassport(keys, v.team, cards, p2), /operation|decrypt|tag/i);
  const identity = b64(Uint8Array.from({ length: 32 }, (_, i) => (i === 0 ? 1 : 0)));
  const badCard = await sealCard(k2, v.team, v.other.member, { name: NAMES.other, keys: { ...v.other.publics, ed25519: identity } });
  await refused("E1a card with the identity point as its key", () => openCard(k2, v.team, v.other.member, badCard), /small order/);
  const pPlus1 = b64(Buffer.from("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "hex"));
  const badCard2 = await sealCard(k2, v.team, v.other.member, { name: NAMES.other, keys: { ...v.other.publics, ed25519: pPlus1 } });
  await refused("E1b card with a non-canonical key (y = p + 1)", () => openCard(k2, v.team, v.other.member, badCard2), /not canonical/);
  await refused("B1 sig without its padding", () => openRecord(keys, v.team, cards, { ...r0, sig: r0.sig.replace(/=+$/, "") }), /canonical base64/);
  await refused("B2 nonce with a leading space", () => openRecord(keys, v.team, cards, { ...r0, nonce: " " + r0.nonce }), /canonical base64/);
  const last = r0.sig.replace(/=+$/, "").slice(-1);
  const tweaked = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(last) ^ 1)];
  await refused("B3 sig with only its trailing bits changed", () => openRecord(keys, v.team, cards, { ...r0, sig: r0.sig.replace(/.(=+)$/, `${tweaked}$1`) }), /canonical base64/);
  await refused("I1 invite code with the bkt2. prefix", async () => readCode("bkt2." + v.invite.code.slice(5), v.team), /bkt3/);
  console.log(`v3(js): ${file} PASSES`);
}

const [cmd, arg] = process.argv.slice(2);
await (cmd === "make" ? make(arg) : check(arg));
