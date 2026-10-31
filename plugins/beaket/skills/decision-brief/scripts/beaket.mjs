#!/usr/bin/env node
// Beaket team records: share decision records with your team, end-to-end encrypted.
// Beaket keeps them as ciphertext and never receives a key. Each member has their own.
// Beside each record Beaket keeps its passport in the clear: a label of a few words, the owner,
// the dates, a state, the links and who answered what about it. Never the text.
//
//   node beaket.mjs team create [--server URL] [--name N]   make a team; you are its first manager
//   node beaket.mjs team invite [--manager]                 invite one person; the code goes to the clipboard and a private file
//   node beaket.mjs team join [--file F | code] [--name N]  join with an invite code, read from the clipboard by default
//   node beaket.mjs team members                            who is in the team, with their role
//   node beaket.mjs team remove <name or id>                remove one member (managers): they are refused at once, and new records use a new key
//   node beaket.mjs team log [--all]                        who joined, pushed, pulled, withdrew and removed what, and when
//   node beaket.mjs team reader [--print]                   make a read key for another AI (managers): it reads only the passports, through the window
//   node beaket.mjs team readers                            the team's read keys: who made each, when it was last used, whether it was revoked
//   node beaket.mjs team revoke-reader <id>                 revoke a read key (managers): the window refuses it at once
//
// An invite code opens the team's key once, within a day. It never goes to standard output unless you
// ask with --print, so that it stays out of an AI assistant's conversation, which is sent to its model.
// The default server, stg.beaket.com, is Beaket's beta; Beaket will run on beaket.com later.
//   node beaket.mjs status                       is this machine in a team, and where are its records
//   node beaket.mjs paths                        the config, cache and private folders of this machine
//   node beaket.mjs push <file>...               encrypt and share decision records (never one marked private), each with its passport
//   node beaket.mjs answer <file or id> <answer>   question | unchanged | changed: answer about a decision; Beaket keeps who, what and when
//   node beaket.mjs passports                    the team's passports: label, owner, dates, state, links and trail, as Beaket holds them
//   node beaket.mjs unshared [folder]            list the records in decisions/ not yet shared, and the private ones
//   node beaket.mjs remove <file>                withdraw a shared record
//   node beaket.mjs pull                         fetch and decrypt the team's records
//   node beaket.mjs index                        list the team's newest records
//   node beaket.mjs verify                       the SHA-256 of this script, and whether every copy of it in the plugin is the same
//   node beaket.mjs session-start [--json]       for the SessionStart hook: pull, then print the index (--json for GitHub Copilot)
import { webcrypto as crypto, createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { homedir, userInfo } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_SERVER = "https://stg.beaket.com";
const onBeta = (server) => (server === DEFAULT_SERVER ? ` It is Beaket's beta server; Beaket will run on beaket.com later.` : "");
const HOOK_TIMEOUT_MS = 3000;
const INDEX_SIZE = 30;
const CONFIG_DIR = process.env.BEAKET_CONFIG_DIR ?? join(homedir(), ".config", "beaket");
const CONFIG = join(CONFIG_DIR, "team.json");
const CACHE_ROOT = process.env.BEAKET_CACHE_DIR ?? join(homedir(), ".cache", "beaket", "teams");
const JOIN_FILE = join(CONFIG_DIR, "join-code");
const READER_FILE = join(CONFIG_DIR, "reader-key");
// Records the person keeps to themselves, outside any repository.
const PRIVATE_DIR = join(CONFIG_DIR, "private");
const ID_LINE = /^<!-- beaket-record: ([0-9a-f-]{36}) -->\n/;
// A record the person keeps to themselves; push refuses it.
const PRIVATE = /^<!-- beaket-private -->$/m;
const enc = new TextEncoder();
const dec = new TextDecoder();

const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const fromB64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
const random = (n) => crypto.getRandomValues(new Uint8Array(n));
const randomId = () => b64url(random(16));
const sha256 = (s) => createHash("sha256").update(s).digest("hex");

// --- Keys (ADR-020) ---
// A team key (32 bytes, one per epoch) never leaves members' machines unwrapped. HKDF turns it
// into a key per use: "records", "members" (cards) and "previous" (the key of the epoch before).
// It reaches a member wrapped to their X25519 public key; an invite seals it with the invite's secret.

const SALT = enc.encode("beaket-team-v2");

async function hkdfKey(bytes, info) {
  const base = await crypto.subtle.importKey("raw", bytes, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: SALT, info: enc.encode(info) }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function hkdfBits(bytes, info) {
  const base = await crypto.subtle.importKey("raw", bytes, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: SALT, info: enc.encode(info) }, base, 256));
}

async function seal(key, plain, aad) {
  const nonce = random(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: enc.encode(aad) }, key, plain));
  return b64(Buffer.concat([nonce, ct]));
}

async function unseal(key, blob, aad) {
  const bytes = fromB64(blob);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12), additionalData: enc.encode(aad) }, key, bytes.slice(12)));
}

async function keyPair() {
  const pair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  return {
    publicKey: b64(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))),
    privateKey: b64(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))),
  };
}

const importPublic = (b) => crypto.subtle.importKey("raw", fromB64(b), { name: "X25519" }, false, []);
const importPrivate = (b) => crypto.subtle.importKey("pkcs8", fromB64(b), { name: "X25519" }, false, ["deriveBits"]);

// The team key, wrapped to a member's public key: an ephemeral X25519 exchange, then HKDF and AES-GCM.
async function wrap(teamKey, publicKey, aad) {
  const eph = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: await importPublic(publicKey) }, eph.privateKey, 256));
  const sealed = fromB64(await seal(await hkdfKey(shared, "wrap"), teamKey, aad));
  return b64(Buffer.concat([new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey)), sealed]));
}

async function unwrap(blob, privateKey, aad) {
  const bytes = fromB64(blob);
  const eph = await crypto.subtle.importKey("raw", bytes.slice(0, 32), { name: "X25519" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: eph }, await importPrivate(privateKey), 256));
  return unseal(await hkdfKey(shared, "wrap"), b64(bytes.slice(32)), aad);
}

const wrapAad = (team, member, epoch) => `${team}/${member}/${epoch}`;
const cardAad = (team, member) => `${team}/${member}`;
const sealCard = async (teamKey, team, member, card) => seal(await hkdfKey(teamKey, "members"), enc.encode(JSON.stringify(card)), cardAad(team, member));
const openCard = async (teamKey, team, member, blob) => JSON.parse(dec.decode(await unseal(await hkdfKey(teamKey, "members"), blob, cardAad(team, member))));

// An invite's secret gives the token Beaket checks by its hash, and the key that seals the team key.
const inviteToken = async (secret) => b64url(await hkdfBits(fromB64(secret), "invite"));
const inviteKey = (secret) => hkdfKey(fromB64(secret), "invite-key");

const keyOf = (config, epoch) => {
  const k = config.keys?.[epoch];
  return k ? fromB64(k) : null;
};

// --- This machine's team ---

function readConfig() {
  if (!existsSync(CONFIG)) return null;
  return JSON.parse(readFileSync(CONFIG, "utf8"));
}

function writeConfig(config) {
  mkdirSync(join(CONFIG, ".."), { recursive: true });
  writeFileSync(CONFIG, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
  chmodSync(CONFIG, 0o600);
}

const cacheDir = (c) => join(CACHE_ROOT, c.team);

function personName(rest) {
  const at = rest.indexOf("--name");
  if (at >= 0 && rest[at + 1]) return rest[at + 1];
  const git = spawnSync("git", ["config", "user.name"], { encoding: "utf8" });
  return (git.status === 0 && git.stdout.trim()) || userInfo().username;
}

const CLIPBOARD = {
  darwin: { copy: ["pbcopy"], paste: ["pbpaste"] },
  win32: { copy: ["clip"], paste: ["powershell", "-NoProfile", "-Command", "Get-Clipboard"] },
  linux: process.env.WAYLAND_DISPLAY ? { copy: ["wl-copy"], paste: ["wl-paste", "-n"] } : { copy: ["xclip", "-selection", "clipboard"], paste: ["xclip", "-selection", "clipboard", "-o"] },
}[process.platform];

function toClipboard(text) {
  if (!CLIPBOARD || process.env.BEAKET_NO_CLIPBOARD) return false;
  const [bin, ...args] = CLIPBOARD.copy;
  return spawnSync(bin, args, { input: text }).status === 0;
}

function fromClipboard() {
  if (!CLIPBOARD || process.env.BEAKET_NO_CLIPBOARD) return "";
  const [bin, ...args] = CLIPBOARD.paste;
  const r = spawnSync(bin, args, { encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim() : "";
}

// Keep the invite code in a file only its owner can read, and on the clipboard; print it only on request.
function handOut(code, expiresAt, print) {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(JOIN_FILE, code + "\n", { mode: 0o600 });
  chmodSync(JOIN_FILE, 0o600);
  if (print) return code;
  const copied = toClipboard(code);
  return (
    `The invite code is ${copied ? "on your clipboard and " : ""}in ${JOIN_FILE} (readable only by you). ` +
    `It lets one person join, once, until ${expiresAt}. Send it to that person in a private message. ` +
    "Do not paste it into an AI assistant: they join with `team join`, which reads it from their clipboard."
  );
}

// A Cloudflare Access service token, when the server sits behind one.
function accessHeaders() {
  const file = join(CONFIG_DIR, "access");
  if (!existsSync(file)) return {};
  const [id, secret] = readFileSync(file, "utf8").split("\n").map((s) => s.trim());
  return id && secret ? { "cf-access-client-id": id, "cf-access-client-secret": secret } : {};
}

class BeaketError extends Error {
  constructor(status, body) {
    super(`Beaket answered ${status}: ${body.slice(0, 300)}`);
    this.status = status;
  }
}

async function request(server, method, path, body, authorization, timeoutMs) {
  const response = await fetch(`${server}${path}`, {
    method,
    redirect: "manual",
    signal: timeoutMs ? AbortSignal.timeout(timeoutMs) : undefined,
    headers: { ...accessHeaders(), ...(authorization ? { authorization } : {}), ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (response.status >= 300 && response.status < 400) throw new Error(`${server} sent this to a sign-in page; it is behind Cloudflare Access.`);
  if (!response.ok) throw new BeaketError(response.status, await response.text());
  return response.json();
}

const call = (config, method, path, body, timeoutMs) => request(config.server, method, path, body, `Bearer ${config.member}.${config.token}`, timeoutMs);

// The current team key, unwrapped with this member's private key, and every earlier one, each opened by the next.
async function refreshKeys(config) {
  const got = await call(config, "GET", `/api/teams/${config.team}/keys`);
  const keys = { [got.epoch]: b64(await unwrap(got.wrapped, config.privateKey, wrapAad(config.team, config.member, got.epoch))) };
  const previous = Object.fromEntries(got.epochs.map((e) => [e.epoch, e.previous]));
  for (let e = got.epoch; e > 1; e--) {
    const opened = await unseal(await hkdfKey(fromB64(keys[e]), "previous"), previous[e], `${config.team}/${e}`);
    keys[e - 1] = b64(opened);
  }
  const fresh = { ...config, epoch: got.epoch, keys };
  writeConfig(fresh);
  return fresh;
}

async function sealRecord(config, id, name, text) {
  const key = await hkdfKey(keyOf(config, config.epoch), "records");
  const nonce = random(12);
  const data = enc.encode(JSON.stringify({ name, text }));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: enc.encode(`${config.team}/${id}/${config.epoch}`) }, key, data);
  return { epoch: config.epoch, nonce: b64(nonce), ciphertext: b64(new Uint8Array(ciphertext)) };
}

async function openRecord(config, record) {
  const key = await hkdfKey(keyOf(config, record.epoch), "records");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(record.nonce), additionalData: enc.encode(`${config.team}/${record.id}/${record.epoch}`) },
    key,
    fromB64(record.ciphertext),
  );
  return JSON.parse(dec.decode(plain));
}

// A push sealed with an older key is refused (409); fetch the current key and push again.
async function pushRecord(config, id, name, text) {
  try {
    return { config, ...(await call(config, "PUT", `/api/teams/${config.team}/records/${id}`, await sealRecord(config, id, name, text))) };
  } catch (error) {
    if (error.status !== 409) throw error;
    const fresh = await refreshKeys(config);
    return { config: fresh, ...(await call(fresh, "PUT", `/api/teams/${fresh.team}/records/${id}`, await sealRecord(fresh, id, name, text))) };
  }
}

function needTeam() {
  const config = readConfig();
  if (!config) {
    console.error("This machine is in no Beaket team. Make one with `team create`, or join with an invite code (`team join`).");
    process.exit(2);
  }
  if (!config.member) {
    console.error(`${CONFIG} is from a team with one shared code, which Beaket no longer serves. Remove that file, then ask a manager of your team for an invite, or make a new team.`);
    process.exit(2);
  }
  return config;
}

// The members with the names on their cards; a card that does not open, or names another public key, is marked.
async function members(config) {
  const { members: list } = await call(config, "GET", `/api/teams/${config.team}/members`);
  return Promise.all(
    list.map(async (m) => {
      try {
        const card = await openCard(keyOf(config, m.cardEpoch), config.team, m.id, m.card);
        return { ...m, name: card.name, verified: card.publicKey === m.publicKey };
      } catch {
        return { ...m, name: `(unknown ${m.id.slice(0, 6)})`, verified: false };
      }
    }),
  );
}

// The record's id lives in its first line, so that every member pushes to the same record.
function recordId(file) {
  const text = readFileSync(file, "utf8");
  if (PRIVATE.test(text)) throw new Error(`${file} is marked private (<!-- beaket-private -->), so it is not shared.`);
  const found = ID_LINE.exec(text);
  if (found) return { id: found[1], text };
  const id = crypto.randomUUID();
  const withId = `<!-- beaket-record: ${id} -->\n${text}`;
  writeFileSync(file, withId);
  return { id, text: withId };
}

// The cached file of a record: its name, or the name with its id when two records share it.
function cachePath(dir, id, name) {
  const plain = join(dir, basename(name));
  if (!existsSync(plain)) return plain;
  const other = ID_LINE.exec(readFileSync(plain, "utf8"))?.[1];
  return other === id ? plain : join(dir, basename(name).replace(/\.md$/, "") + `-${id.slice(0, 8)}.md`);
}

function findCached(dir, id) {
  if (!existsSync(dir)) return null;
  for (const f of readdirSync(dir)) {
    if (!f.endsWith(".md")) continue;
    if (ID_LINE.exec(readFileSync(join(dir, f), "utf8"))?.[1] === id) return join(dir, f);
  }
  return null;
}

// --- Passports (docs/specs/passport.md) ---
// What Beaket keeps of a record in the clear, read from the record's own lines: a label of a few
// words (the `Label:` line, or the file name's words), the owner, the dates, and the links of its
// Sources, Rests on and Supersedes. Nothing of Decision, Why or Rejected.

const MAX_LABEL = 80;
const line = (text, names) => new RegExp(`^- (?:${names.join("|")}):\\s*(.+?)\\s*$`, "m").exec(text)?.[1];
const day = (s) => (s && /^\d{4}-\d{2}-\d{2}/.test(s) ? s.slice(0, 10) : undefined);

function section(text, names) {
  const heading = new RegExp(`^## (?:${names.join("|")})\\s*$`, "m").exec(text);
  if (!heading) return "";
  const rest = text.slice(heading.index + heading[0].length);
  const next = /^## /m.exec(rest);
  return next ? rest.slice(0, next.index) : rest;
}

// Each link of a section: a URL, or a path such as decisions/x.md or docs/adr/ADR-027.md, or a record id.
function linksOf(block) {
  const found = new Set();
  for (const m of block.matchAll(/https?:\/\/[^\s)>\]]+/g)) found.add(m[0].replace(/[.,;:]+$/, ""));
  for (const m of block.matchAll(/(?:^|[\s(\[])((?:decisions|docs)\/[^\s)\]]+\.md)/g)) found.add(m[1]);
  for (const m of block.matchAll(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g)) found.add(m[0]);
  return [...found].map((href) => href.slice(0, 500));
}

function passportOf(file, text) {
  const title = /^# (.+)$/m.exec(text)?.[1] ?? basename(file, ".md");
  const slugWords = basename(file, ".md").replace(/^\d{4}-\d{2}-\d{2}-/, "").replace(/-/g, " ");
  const label = (line(text, ["Label", "라벨", "ラベル"]) ?? slugWords).slice(0, MAX_LABEL);
  const owner = (line(text, ["Decided by", "결정자", "決定者", "決めた人"]) ?? userInfo().username).slice(0, 80);
  const decided = day(line(text, ["Date", "날짜", "日付"])) ?? new Date().toISOString().slice(0, 10);
  const reviewBy = day(line(text, ["Review by", "다시 볼 날", "見直す日"])) ?? null;
  const links = [
    ...linksOf(section(text, ["Sources", "출처", "ソース", "参照"])).map((href) => ({ rel: "source", href })),
    ...linksOf(section(text, ["Rests on", "기대는 결정", "前提とする決定"])).map((href) => ({ rel: "rests-on", href })),
    ...linksOf(line(text, ["Supersedes", "대체하는 결정", "置き換える決定"]) ?? "").map((href) => ({ rel: "supersedes", href })),
  ].slice(0, 50);
  return { title, passport: { label, owner, decided, reviewBy, links } };
}

const PASSPORTS = (c) => join(cacheDir(c), "passports.json");
const readPassports = (c) => (existsSync(PASSPORTS(c)) ? JSON.parse(readFileSync(PASSPORTS(c), "utf8")) : {});

// The team's passports changed since the last pull, kept beside the records as passports.json.
async function pullPassports(config, timeoutMs) {
  const held = readPassports(config);
  let after = config.passportCursor ?? 0;
  for (;;) {
    const page = await call(config, "GET", `/api/teams/${config.team}/passports?after=${after}`, null, timeoutMs);
    for (const p of page.passports) {
      held[p.id] = p;
      after = p.seq;
    }
    if (!page.more) break;
  }
  mkdirSync(cacheDir(config), { recursive: true });
  writeFileSync(PASSPORTS(config), JSON.stringify(held, null, 2) + "\n");
  const fresh = { ...config, passportCursor: after };
  writeConfig(fresh);
  return fresh;
}

async function pull(start, timeoutMs) {
  let config = start;
  const dir = cacheDir(config);
  mkdirSync(dir, { recursive: true });
  let changed = 0;
  let after = config.cursor ?? 0;
  for (;;) {
    const page = await call(config, "GET", `/api/teams/${config.team}/records?after=${after}`, null, timeoutMs);
    for (const r of page.records) {
      const old = findCached(dir, r.id);
      if (old) rmSync(old);
      if (r.ciphertext) {
        if (!keyOf(config, r.epoch)) config = await refreshKeys(config);
        const { name, text } = await openRecord(config, r);
        writeFileSync(cachePath(dir, r.id, name), text);
      }
      after = r.seq;
      changed++;
    }
    if (!page.more) break;
  }
  config = { ...config, cursor: after };
  writeConfig(config);
  config = await pullPassports(config, timeoutMs);
  return { changed, dir, config };
}

function index(config) {
  const dir = cacheDir(config);
  if (!existsSync(dir)) return [];
  const passports = readPassports(config);
  return readdirSync(dir)
    .filter((f) => f.endsWith(".md"))
    .map((f) => {
      const text = readFileSync(join(dir, f), "utf8");
      const title = /^# (.+)$/m.exec(text)?.[1] ?? f;
      const date = /^- (?:Date|날짜|日付):\s*(\S+)/m.exec(text)?.[1] ?? statSync(join(dir, f)).mtime.toISOString().slice(0, 10);
      const id = ID_LINE.exec(text)?.[1];
      const state = (id && passports[id]?.state) ?? "valid";
      return { file: f, title, date, state };
    })
    .sort((a, b) => b.date.localeCompare(a.date))
    .slice(0, INDEX_SIZE);
}

const [cmd, sub, ...rest] = process.argv.slice(2);
const self = fileURLToPath(import.meta.url);

try {
  if (cmd === "team" && sub === "create") {
    if (readConfig()) throw new Error(`This machine is already in a team (${CONFIG}). Remove that file first to make another.`);
    const at = rest.indexOf("--server");
    const server = (at >= 0 ? rest[at + 1] : process.env.BEAKET_URL ?? DEFAULT_SERVER).replace(/\/+$/, "");
    const team = randomId();
    const member = randomId();
    const token = b64url(random(32));
    const pair = await keyPair();
    const teamKey = random(32);
    const name = personName(rest);
    await request(server, "POST", "/api/teams", {
      team,
      member,
      tokenHash: sha256(token),
      publicKey: pair.publicKey,
      wrapped: await wrap(teamKey, pair.publicKey, wrapAad(team, member, 1)),
      card: await sealCard(teamKey, team, member, { name, publicKey: pair.publicKey }),
    });
    writeConfig({ server, team, member, token, name, role: "manager", ...pair, epoch: 1, keys: { 1: b64(teamKey) }, cursor: 0 });
    console.log(`Made a team at ${server}, with you (${name}) as its manager.${onBeta(server)} Invite each person with \`team invite\`; an invite lets one person join, once, within a day.`);
  } else if (cmd === "team" && sub === "invite") {
    let config = needTeam();
    if (config.role !== "manager") throw new Error("Only a manager of the team can invite. Ask one of them.");
    config = await refreshKeys(config);
    const secret = b64(random(32));
    const role = rest.includes("--manager") ? "manager" : "member";
    const wrapped = await seal(await inviteKey(secret), keyOf(config, config.epoch), `${config.team}/invite`);
    const made = await call(config, "POST", `/api/teams/${config.team}/invites`, { tokenHash: sha256(await inviteToken(secret)), role, epoch: config.epoch, wrapped });
    const code = "bkt2." + b64url(enc.encode(JSON.stringify({ server: config.server, team: config.team, secret })));
    console.log(`Made an invite as ${role}. ${handOut(code, made.expiresAt, rest.includes("--print"))}`);
  } else if (cmd === "team" && sub === "join") {
    const at = rest.indexOf("--file");
    const code = (at >= 0 ? readFileSync(rest[at + 1], "utf8") : rest[0] && !rest[0].startsWith("--") ? rest[0] : fromClipboard()).trim();
    if (code.startsWith("bkt1.")) throw new Error("This is a code of a team with one shared code, which Beaket no longer serves. Ask a manager of the team for an invite (`team invite`).");
    if (!code.startsWith("bkt2.")) throw new Error("No invite code found: copy the code your teammate sent (it starts with bkt2.) and run this again, or pass --file <file holding it>.");
    const { server, team, secret } = JSON.parse(dec.decode(Buffer.from(code.slice(5), "base64url")));
    const existing = readConfig();
    if (existing?.team === team && existing.member) throw new Error(`This machine is already in this team (${CONFIG}).`);
    if (existing && !rest.includes("--switch")) throw new Error(`This machine is already in another team (${CONFIG}). To leave it for this one, run this again with --switch.`);
    const auth = `Invite ${await inviteToken(secret)}`;
    let invite;
    try {
      invite = await request(server, "GET", `/api/teams/${team}/invite`, null, auth);
    } catch (error) {
      if (error.status === 401) throw new Error("This invite was already used, has expired, or was cancelled when someone was removed. Ask a manager of the team for a new one.");
      throw error;
    }
    const teamKey = await unseal(await inviteKey(secret), invite.wrapped, `${team}/invite`);
    const member = randomId();
    const token = b64url(random(32));
    const pair = await keyPair();
    const name = personName(rest);
    const joined = await request(
      server,
      "POST",
      `/api/teams/${team}/members`,
      {
        member,
        tokenHash: sha256(token),
        publicKey: pair.publicKey,
        wrapped: await wrap(teamKey, pair.publicKey, wrapAad(team, member, invite.epoch)),
        card: await sealCard(teamKey, team, member, { name, publicKey: pair.publicKey }),
        epoch: invite.epoch,
      },
      auth,
    );
    if (existing) rmSync(cacheDir(existing), { recursive: true, force: true });
    let config = { server, team, member, token, name, role: joined.role, ...pair, epoch: invite.epoch, keys: { [invite.epoch]: b64(teamKey) }, cursor: 0 };
    writeConfig(config);
    config = await refreshKeys(config);
    const { changed, dir } = await pull(config);
    rmSync(JOIN_FILE, { force: true });
    console.log(`Joined the team at ${server} as ${name} (${joined.role}).${onBeta(server)} ${changed} change(s) pulled; the records are in ${dir}.`);
  } else if (cmd === "team" && sub === "members") {
    const config = await refreshKeys(needTeam());
    for (const m of await members(config)) {
      const state = m.removedAt ? `removed ${m.removedAt.slice(0, 10)}` : `joined ${m.joinedAt.slice(0, 10)}`;
      const warn = m.verified ? "" : " — its card does not match its key; do not trust this entry";
      console.log(`- ${m.name}${m.id === config.member ? " (you)" : ""}: ${m.role}, ${state}, id ${m.id}${warn}`);
    }
  } else if (cmd === "team" && sub === "remove") {
    let config = needTeam();
    if (config.role !== "manager") throw new Error("Only a manager of the team can remove a member. Ask one of them.");
    if (!rest[0]) throw new Error("Name the member to remove, by name or id (see `team members`).");
    config = await refreshKeys(config);
    const list = await members(config);
    const active = list.filter((m) => !m.removedAt);
    const wanted = rest.join(" ").toLowerCase();
    const found = active.filter((m) => m.id === rest[0] || m.name.toLowerCase() === wanted);
    if (found.length === 0) throw new Error(`No current member is named ${rest.join(" ")}. See \`team members\`.`);
    if (found.length > 1) throw new Error(`More than one member is named ${rest.join(" ")}; remove one by id: ${found.map((m) => m.id).join(", ")}.`);
    const gone = found[0];
    if (gone.id === config.member) throw new Error("You cannot remove yourself; ask another manager.");
    const staying = active.filter((m) => m.id !== gone.id);
    const forged = staying.filter((m) => !m.verified);
    if (forged.length) throw new Error(`The card of ${forged.map((m) => m.id).join(", ")} does not match the key Beaket lists, so no new key was made. Tell Beaket.`);
    const epoch = config.epoch + 1;
    const fresh = random(32);
    await call(config, "POST", `/api/teams/${config.team}/rotate`, {
      remove: gone.id,
      epoch,
      previous: await seal(await hkdfKey(fresh, "previous"), keyOf(config, config.epoch), `${config.team}/${epoch}`),
      keys: await Promise.all(staying.map(async (m) => ({ member: m.id, wrapped: await wrap(fresh, m.publicKey, wrapAad(config.team, m.id, epoch)) }))),
      cards: await Promise.all(staying.map(async (m) => ({ member: m.id, card: await sealCard(fresh, config.team, m.id, { name: m.name, publicKey: m.publicKey }) }))),
    });
    await refreshKeys(config);
    console.log(
      `Removed ${gone.name}. Beaket refuses them from now on, and records pushed from now on use a new key that only the ${staying.length} remaining member(s) have. ` +
        "They keep the copies they already pulled. Invites not yet used were cancelled, and the read keys they made were revoked.",
    );
  } else if (cmd === "team" && sub === "log") {
    const config = await refreshKeys(needTeam());
    const names = Object.fromEntries((await members(config)).map((m) => [m.id, m.name]));
    const titles = {};
    const dir = cacheDir(config);
    if (existsSync(dir))
      for (const f of readdirSync(dir).filter((f) => f.endsWith(".md"))) {
        const text = readFileSync(join(dir, f), "utf8");
        const id = ID_LINE.exec(text)?.[1];
        if (id) titles[id] = /^# (.+)$/m.exec(text)?.[1] ?? f;
      }
    const entries = [];
    for (let after = 0; ; ) {
      const page = await call(config, "GET", `/api/teams/${config.team}/log?after=${after}`);
      entries.push(...page.entries);
      if (!page.more || page.entries.length === 0) break;
      after = page.entries.at(-1).seq;
    }
    // An invite is shown by who used it.
    const usedBy = Object.fromEntries(entries.filter((e) => e.action === "joined").map((e) => [e.subject, names[e.member] ?? e.member]));
    const describe = (e) => {
      if (e.action === "invited") {
        const [id, role] = (e.subject ?? "").split(" ");
        return `${usedBy[id] ? usedBy[id] : "someone (not used)"} as ${role}`;
      }
      if (e.action === "joined") return "";
      if (e.action === "removed") return names[e.subject] ?? e.subject;
      if (e.action === "pushed" || e.action === "withdrew" || e.action === "passport") return titles[e.subject] ?? `record ${e.subject}`;
      if (e.action === "answered") {
        const [id, answer] = (e.subject ?? "").split(" ");
        return `${answer} about ${titles[id] ?? `record ${id}`}`;
      }
      if (e.action === "pulled") return `changes ${e.subject.replace("-", " to ")}`;
      if (e.action === "window") return (e.subject ?? "").split(" ")[1] ?? "";
      return e.subject ?? "";
    };
    const shown = rest.includes("--all") ? entries : entries.slice(-50);
    for (const e of shown) {
      const subject = describe(e);
      const by = names[e.member] ?? (e.action === "window" ? `read key ${e.member}` : e.member);
      console.log(`${e.at.slice(0, 16).replace("T", " ")} UTC  ${by}  ${e.action}${subject ? ` ${subject}` : ""}`);
    }
    if (shown.length < entries.length) console.log(`(${entries.length - shown.length} earlier line(s); --all shows them)`);
  } else if (cmd === "team" && sub === "reader") {
    // The window (docs/specs/window.md): a read key for another vendor's AI, which gets passports and links, never text.
    const config = needTeam();
    if (config.role !== "manager") throw new Error("Only a manager of the team can make a read key. Ask one of them.");
    const id = randomId();
    const token = b64url(random(32));
    const made = await call(config, "POST", `/api/teams/${config.team}/readers`, { id, tokenHash: sha256(token) });
    const key = `${id}.${token}`;
    mkdirSync(CONFIG_DIR, { recursive: true });
    writeFileSync(READER_FILE, key + "\n", { mode: 0o600 });
    chmodSync(READER_FILE, 0o600);
    const copied = rest.includes("--print") ? false : toClipboard(key);
    const url = `${config.server}${made.url}`;
    console.log(
      [
        `Made read key ${id}. It reads this team's passports (label, owner, dates, state, links), never a record's text, and can change nothing.`,
        `The window: ${url} (MCP over streamable HTTP). The other tool sends the header \`Authorization: Bearer <key>\`.`,
        rest.includes("--print") ? `The key: ${key}` : `The key is ${copied ? "on your clipboard and " : ""}in ${READER_FILE}, readable only by you; paste it into the other tool's settings, not into a conversation.`,
        `For example, in Claude Code: claude mcp add --transport http beaket-decisions ${url} --header "Authorization: Bearer <key>"`,
        `Revoke it with \`team revoke-reader ${id}\`.`,
      ].join("\n"),
    );
  } else if (cmd === "team" && sub === "readers") {
    const config = await refreshKeys(needTeam());
    const names = Object.fromEntries((await members(config)).map((m) => [m.id, m.name]));
    const { readers } = await call(config, "GET", `/api/teams/${config.team}/readers`);
    if (readers.length === 0) console.log("The team has no read keys.");
    for (const r of readers) {
      const state = r.revokedAt ? `revoked ${r.revokedAt.slice(0, 10)}` : r.usedAt ? `last used ${r.usedAt.slice(0, 16).replace("T", " ")} UTC` : "never used";
      console.log(`- ${r.id}: made by ${names[r.createdBy] ?? r.createdBy} on ${r.createdAt.slice(0, 10)}, ${state}`);
    }
  } else if (cmd === "team" && sub === "revoke-reader") {
    const config = needTeam();
    if (config.role !== "manager") throw new Error("Only a manager of the team can revoke a read key. Ask one of them.");
    if (!rest[0]) throw new Error("Name the read key to revoke, by id (see `team readers`).");
    await call(config, "DELETE", `/api/teams/${config.team}/readers/${rest[0]}`);
    console.log(`Revoked read key ${rest[0]}. The window refuses it from now on.`);
  } else if (cmd === "status") {
    const config = needTeam();
    console.log(`Team ${config.team} at ${config.server}, as ${config.name} (${config.role}).${onBeta(config.server)} Records: ${cacheDir(config)}. Script: ${self}`);
  } else if (cmd === "push") {
    let config = needTeam();
    for (const file of [sub, ...rest].filter(Boolean)) {
      const { id, text } = recordId(file);
      const pushed = await pushRecord(config, id, basename(file), text);
      config = pushed.config;
      const { passport } = passportOf(file, text);
      const stamped = await call(config, "PUT", `/api/teams/${config.team}/passports/${id}`, passport);
      console.log(`Shared ${file} (record ${id}, change ${pushed.seq}). Its passport, in the clear: "${passport.label}", ${passport.owner}, ${passport.decided}, ${passport.links.length} link(s), ${stamped.state}.`);
    }
    await pull(config);
  } else if (cmd === "answer") {
    const config = needTeam();
    const answer = rest[0];
    if (!sub || !["question", "unchanged", "changed"].includes(answer)) throw new Error("Usage: answer <record file or id> question|unchanged|changed");
    const id = existsSync(sub) ? ID_LINE.exec(readFileSync(sub, "utf8"))?.[1] : sub;
    if (!id) throw new Error(`${sub} was never shared, so it has no passport. Share it first (push).`);
    const got = await call(config, "POST", `/api/teams/${config.team}/passports/${id}`, { answer });
    await pullPassports(config);
    console.log(`Answered "${answer}" about record ${id}; its state is now ${got.state}. Beaket keeps who answered, what and when, and none of the words.`);
  } else if (cmd === "passports") {
    const config = await pullPassports(needTeam());
    const held = Object.values(readPassports(config)).sort((a, b) => b.seq - a.seq);
    if (held.length === 0) console.log("The team has no passports yet.");
    for (const p of held) {
      const trail = p.trail.length ? `; ${p.trail.map((a) => `${a.answer} ${a.at.slice(0, 10)}`).join(", ")}` : "";
      console.log(`- ${p.state}: "${p.label}" — ${p.owner}, ${p.decided}${p.reviewBy ? `, review by ${p.reviewBy}` : ""}, ${p.links.length} link(s), record ${p.id}${trail}`);
    }
  } else if (cmd === "paths") {
    console.log(`config: ${CONFIG}\ncache: ${CACHE_ROOT}\nprivate: ${PRIVATE_DIR}`);
  } else if (cmd === "unshared") {
    const dir = sub ?? join(process.cwd(), "decisions");
    const files = existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith(".md")).sort() : [];
    if (files.length === 0) console.log(`No records in ${dir}.`);
    for (const f of files) {
      const text = readFileSync(join(dir, f), "utf8");
      const title = /^# (.+)$/m.exec(text)?.[1] ?? f;
      const state = PRIVATE.test(text) ? "private" : ID_LINE.test(text) ? "shared" : "not shared";
      console.log(`- ${state}: ${join(dir, f)} — ${title}`);
    }
  } else if (cmd === "remove") {
    const config = needTeam();
    const found = ID_LINE.exec(readFileSync(sub, "utf8"));
    if (!found) throw new Error(`${sub} was never shared.`);
    await call(config, "DELETE", `/api/teams/${config.team}/records/${found[1]}`);
    await pull(config);
    console.log(`Withdrew ${sub} from the team.`);
  } else if (cmd === "pull") {
    const config = needTeam();
    try {
      const { changed, dir } = await pull(config);
      console.log(`${changed} change(s). The team's records are in ${dir}.`);
    } catch (error) {
      const why = error.status === 401 ? "this member was removed from the team, or the team is gone" : error.message;
      console.log(`Could not pull (${why}). The records of the last pull are in ${cacheDir(config)}.`);
    }
  } else if (cmd === "verify") {
    // Each skill carries a copy of bin/beaket.mjs in its scripts/ (ADR-021); show that they are one script.
    const here = dirname(self);
    const root = basename(here) === "scripts" ? join(here, "..", "..", "..") : join(here, "..");
    const copies = [join(root, "bin", "beaket.mjs")];
    if (existsSync(join(root, "skills"))) for (const s of readdirSync(join(root, "skills"))) copies.push(join(root, "skills", s, "scripts", "beaket.mjs"));
    const sha = (f) => createHash("sha256").update(readFileSync(f)).digest("hex");
    const mine = sha(self);
    console.log(`This script: ${self}\nSHA-256: ${mine}`);
    let differ = 0;
    for (const f of copies.filter(existsSync)) {
      const same = sha(f) === mine;
      if (!same) differ++;
      console.log(`${same ? "same" : "DIFFERENT"}  ${f}`);
    }
    if (differ) process.exit(1);
  } else if (cmd === "index") {
    const config = needTeam();
    for (const r of index(config)) console.log(`- ${r.title} (${r.date}) — ${r.file}${r.state !== "valid" ? ` [${r.state}]` : ""}`);
  } else if (cmd === "session-start") {
    const config = readConfig();
    if (!config?.member) process.exit(0);
    let note = "";
    try {
      await pull(config, HOOK_TIMEOUT_MS);
    } catch {
      note = " (Beaket could not be reached; these are from the last pull)";
    }
    const list = index(config);
    if (list.length === 0) process.exit(0);
    const text = [
      `Your team's decision records (Beaket)${note}, newest first, in ${cacheDir(config)}:`,
      ...list.map((r) => `- ${r.title} (${r.date}) — ${r.file}${r.state !== "valid" ? ` [${r.state}]` : ""}`),
      "Before changing something one of them covers, read that record and follow it, or ask the person whether it should change. Cite a record by its title, its date and its file name (with its path under decisions/ when the repository has it), never as \"today\" or by a cache path alone.",
      `When a request goes against a record, stop before doing anything and say so in at most five lines: the record's title, date and file name, its decision, and the reason in the decider's words, with one source link. Then ask the person one question only: did the premise change? Check the record's Premises first; a premise the world no longer meets is the contradiction to name. If they say yes, update the record (the change, the date and who, under Changes), share it (node ${self} push <file>) and run node ${self} answer <file> changed; if they say no, run node ${self} answer <file> unchanged and drop or change the action. A record marked [questioned] or [changed] above has an open question or a changed premise: read its Changes before relying on it.`,
      "Say what a record covers and what it does not: a case it does not name (another variant, product or scope) is not settled by it; say it is open and who decided the record, and ask. When someone asks to reopen a decision or switch to another option, give the reason the record has for each option it rejected, not only the one they name, and who to talk to before writing a proposal. When a request follows a record, mention it in one line at most. Mark anything not from a record or the team's sources as your own general knowledge, and before citing a document as current, check it is not superseded or from a cancelled project.",
      `To share a new record: node ${self} push <file>.`,
    ].join("\n");
    // Claude Code and Codex add plain stdout to the session; GitHub Copilot reads only JSON {additionalContext}.
    console.log(sub === "--json" ? JSON.stringify({ additionalContext: text }) : text);
  } else {
    const lines = readFileSync(self, "utf8").split("\n").slice(1);
    console.log(lines.slice(0, lines.findIndex((l) => !l.startsWith("//"))).map((l) => l.replace(/^\/\/ ?/, "")).join("\n"));
  }
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
