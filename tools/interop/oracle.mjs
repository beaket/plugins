#!/usr/bin/env node
// Cross-check the client's crypto with a second implementation (tools/interop/go): each side makes a
// scenario (a member's key pair, a wrapped team key, the key of the epoch before, an invite, a card,
// records at two epochs) and the other side opens it. The crypto is not copied here: it is read from
// plugins/beaket/bin/beaket.mjs on every run, so a change to the script's formats fails this check.
//
//   node tools/interop/oracle.mjs make <out.json>
//   node tools/interop/oracle.mjs check <in.json>
//   node tools/interop/oracle.mjs cross <other binary> [rounds]   JS makes, it checks; it makes, JS checks
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const script = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "plugins", "beaket", "bin", "beaket.mjs");
const source = readFileSync(script, "utf8");
const slice = (from, to) => {
  const a = source.indexOf(from);
  const b = source.indexOf(to, a);
  if (a < 0 || b < 0) throw new Error(`${script} no longer has "${from.trim()}" … "${to.trim()}"; update the slices in ${fileURLToPath(import.meta.url)}.`);
  return source.slice(a, b);
};
const core =
  `import { webcrypto as crypto, createHash } from "node:crypto";\n` +
  slice("\nconst enc = new TextEncoder();", "\n// --- This machine's teams") +
  slice("\nasync function sealRecord(", "\n// A push sealed") +
  "\nexport { enc, dec, b64, b64url, fromB64, random, randomId, sha256, hkdfKey, seal, unseal, keyPair, wrap, unwrap, wrapAad, sealCard, openCard, inviteToken, inviteKey, sealRecord, openRecord };";
const { enc, dec, b64, b64url, fromB64, random, randomId, sha256, hkdfKey, seal, unseal, keyPair, wrap, unwrap, wrapAad, sealCard, openCard, inviteToken, inviteKey, sealRecord, openRecord } =
  await import("data:text/javascript," + encodeURIComponent(core));

// The script's sealRecord and openRecord take a membership; this one holds just the keys.
const membership = (team, epoch, keys) => ({ team, epoch, keys: Object.fromEntries(Object.entries(keys).map(([e, k]) => [e, b64(k)])) });

const EXPECTED = [
  { name: "2026-11-07-kafka-or-sqs.md", text: "# SQS로 간다\n\n- Decided by: 플랫폼 리드\n- Why: 운영 부담 🙂\n" },
  { name: "2026-10-01-old.md", text: "epoch 1 record\n" },
];
const CARD_NAME = "테스트 Person";

async function make(out) {
  const team = randomId();
  const member = randomId();
  const pair = await keyPair();
  const k1 = random(32);
  const k2 = random(32);
  const secret = b64(random(32));
  const record = async (epoch, key, { name, text }) => {
    const id = crypto.randomUUID();
    return { id, ...(await sealRecord(membership(team, epoch, { [epoch]: key }), id, name, text)) };
  };
  const v = {
    team,
    member,
    publicKey: pair.publicKey,
    privateKey: pair.privateKey,
    epoch: 2,
    wrapped: await wrap(k2, pair.publicKey, wrapAad(team, member, 2)),
    previous: { 2: await seal(await hkdfKey(k2, "previous"), k1, `${team}/2`) },
    invite: {
      code: "bkt2." + b64url(enc.encode(JSON.stringify({ server: "https://example.invalid", team, secret }))),
      tokenHash: sha256(await inviteToken(secret)),
      wrapped: await seal(await inviteKey(secret), k2, `${team}/invite`),
    },
    card: await sealCard(k2, team, member, { name: CARD_NAME, publicKey: pair.publicKey }),
    records: [await record(2, k2, EXPECTED[0]), await record(1, k1, EXPECTED[1])],
  };
  writeFileSync(out, JSON.stringify(v, null, 2));
  console.log(`oracle(js): wrote ${out}`);
}

const ok = (c, m) => {
  if (!c) throw new Error(`FAIL: ${m}`);
  console.log(`  ok  ${m}`);
};
const fails = (p) => p.then(() => false, () => true);

async function check(file) {
  const v = JSON.parse(readFileSync(file, "utf8"));
  const k2 = await unwrap(v.wrapped, v.privateKey, wrapAad(v.team, v.member, v.epoch));
  ok(k2.length === 32, "unwrap team key (X25519 pkcs8 private + ephemeral raw public, HKDF wrap, AES-GCM)");
  const k1 = await unseal(await hkdfKey(k2, "previous"), v.previous[2], `${v.team}/2`);
  ok(k1.length === 32, "open epoch 1 key from epoch 2 via 'previous'");
  const { team, secret } = JSON.parse(dec.decode(Buffer.from(v.invite.code.slice(5), "base64url")));
  ok(team === v.team, "invite code bkt2. base64url JSON");
  ok(sha256(await inviteToken(secret)) === v.invite.tokenHash, "invite token = b64url(HKDF bits 'invite'), sha256 hex matches");
  const ik = await unseal(await inviteKey(secret), v.invite.wrapped, `${v.team}/invite`);
  ok(Buffer.compare(Buffer.from(ik), Buffer.from(k2)) === 0, "invite opens the same team key");
  const card = await openCard(k2, v.team, v.member, v.card);
  ok(card.name === CARD_NAME && card.publicKey === v.publicKey, "card opens with 'members' key and team/member AAD");
  const config = membership(v.team, v.epoch, { 1: k1, 2: k2 });
  for (const [i, r] of v.records.entries()) {
    const got = await openRecord(config, r);
    const want = EXPECTED.find((e) => e.name === got.name);
    ok(want && want.text === got.text, `record ${i} (epoch ${r.epoch}) opens, UTF-8 text equal`);
  }
  ok(await fails(openRecord(config, { ...v.records[0], id: v.records[1].id })), "record with swapped id (AAD) is refused");
  ok(await fails(unwrap(v.wrapped, v.privateKey, wrapAad(v.team, v.member, 1))), "wrap with wrong epoch AAD is refused");
  console.log(`oracle(js): ${file} PASSES`);
}

async function cross(other, rounds) {
  const dir = mkdtempSync(join(tmpdir(), "beaket-interop-"));
  const run = (cmd, args) => {
    const r = spawnSync(cmd, args, { encoding: "utf8" });
    if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")} failed:\n${r.stdout}${r.stderr}`);
  };
  try {
    for (let i = 1; i <= rounds; i++) {
      const fromJs = join(dir, `js-${i}.json`);
      const fromOther = join(dir, `other-${i}.json`);
      run(process.execPath, [fileURLToPath(import.meta.url), "make", fromJs]);
      run(other, ["check", fromJs]);
      run(other, ["make", fromOther]);
      run(process.execPath, [fileURLToPath(import.meta.url), "check", fromOther]);
    }
    console.log(`oracle(js): ${rounds} rounds each way with ${other}: all pass`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const [cmd, arg, n] = process.argv.slice(2);
if (cmd === "make") await make(arg);
else if (cmd === "check") await check(arg);
else if (cmd === "cross") await cross(arg, Number(n ?? 20));
else {
  console.error("usage: oracle.mjs make <out.json> | check <in.json> | cross <other binary> [rounds]");
  process.exit(2);
}
