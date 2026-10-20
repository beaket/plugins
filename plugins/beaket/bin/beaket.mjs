#!/usr/bin/env node
// Beaket team records: share decision records with your team, end-to-end encrypted.
// Beaket keeps them as ciphertext and never receives the key.
//
//   node beaket.mjs team create [--server URL]   make a team and print its join code
//   node beaket.mjs team join <code>             join a team with a code from a teammate
//   node beaket.mjs team show                    print this team's join code, to invite someone
//   node beaket.mjs status                       is this machine in a team, and where are its records
//   node beaket.mjs push <file>...               encrypt and share decision records
//   node beaket.mjs remove <file>                withdraw a shared record
//   node beaket.mjs pull                         fetch and decrypt the team's records
//   node beaket.mjs index                        list the team's newest records
//   node beaket.mjs session-start                for the SessionStart hook: pull, then print the index
import { webcrypto as crypto, createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_SERVER = "https://stg.beaket.com";
const HOOK_TIMEOUT_MS = 3000;
const INDEX_SIZE = 30;
const CONFIG_DIR = process.env.BEAKET_CONFIG_DIR ?? join(homedir(), ".config", "beaket");
const CONFIG = join(CONFIG_DIR, "team.json");
const CACHE_ROOT = process.env.BEAKET_CACHE_DIR ?? join(homedir(), ".cache", "beaket", "teams");
const ID_LINE = /^<!-- beaket-record: ([0-9a-f-]{36}) -->\n/;
const enc = new TextEncoder();
const dec = new TextDecoder();

const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const fromB64 = (s) => new Uint8Array(Buffer.from(s, "base64"));

// The secret yields two things: the access token, which Beaket checks by its hash,
// and the AES-256-GCM key, which never leaves this machine.
async function derive(secret) {
  const base = await crypto.subtle.importKey("raw", fromB64(secret), "HKDF", false, ["deriveBits", "deriveKey"]);
  const params = (info) => ({ name: "HKDF", hash: "SHA-256", salt: enc.encode("beaket-team-v1"), info: enc.encode(info) });
  const token = b64url(new Uint8Array(await crypto.subtle.deriveBits(params("access"), base, 256)));
  const key = await crypto.subtle.deriveKey(params("records"), base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  return { token, key };
}

function readConfig() {
  if (!existsSync(CONFIG)) return null;
  return JSON.parse(readFileSync(CONFIG, "utf8"));
}

function writeConfig(config) {
  mkdirSync(join(CONFIG, ".."), { recursive: true });
  writeFileSync(CONFIG, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
  chmodSync(CONFIG, 0o600);
}

const joinCode = (c) => "bkt1." + b64url(enc.encode(JSON.stringify({ server: c.server, team: c.team, secret: c.secret })));
const cacheDir = (c) => join(CACHE_ROOT, c.team);

// A Cloudflare Access service token, when the server sits behind one.
function accessHeaders() {
  const file = join(CONFIG_DIR, "access");
  if (!existsSync(file)) return {};
  const [id, secret] = readFileSync(file, "utf8").split("\n").map((s) => s.trim());
  return id && secret ? { "cf-access-client-id": id, "cf-access-client-secret": secret } : {};
}

async function call(config, method, path, body, timeoutMs) {
  const { token } = await derive(config.secret);
  const response = await fetch(`${config.server}${path}`, {
    method,
    redirect: "manual",
    signal: timeoutMs ? AbortSignal.timeout(timeoutMs) : undefined,
    headers: { ...accessHeaders(), authorization: `Bearer ${token}`, ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (response.status >= 300 && response.status < 400) throw new Error(`${config.server} sent this to a sign-in page; it is behind Cloudflare Access.`);
  if (!response.ok) throw new Error(`Beaket answered ${response.status}: ${(await response.text()).slice(0, 300)}`);
  return response.json();
}

async function seal(config, id, name, text) {
  const { key } = await derive(config.secret);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const data = enc.encode(JSON.stringify({ name, text }));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: enc.encode(`${config.team}/${id}`) }, key, data);
  return { nonce: b64(nonce), ciphertext: b64(new Uint8Array(ciphertext)) };
}

async function open(config, record) {
  const { key } = await derive(config.secret);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromB64(record.nonce), additionalData: enc.encode(`${config.team}/${record.id}`) },
    key,
    fromB64(record.ciphertext),
  );
  return JSON.parse(dec.decode(plain));
}

function needTeam() {
  const config = readConfig();
  if (!config) {
    console.error("This machine is in no Beaket team. Make one with `team create`, or join with `team join <code>`.");
    process.exit(2);
  }
  return config;
}

// The record's id lives in its first line, so that every member pushes to the same record.
function recordId(file) {
  const text = readFileSync(file, "utf8");
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

async function pull(config, timeoutMs) {
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
        const { name, text } = await open(config, r);
        writeFileSync(cachePath(dir, r.id, name), text);
      }
      after = r.seq;
      changed++;
    }
    if (!page.more) break;
  }
  writeConfig({ ...config, cursor: after });
  return { changed, dir };
}

function index(config) {
  const dir = cacheDir(config);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith(".md"))
    .map((f) => {
      const text = readFileSync(join(dir, f), "utf8");
      const title = /^# (.+)$/m.exec(text)?.[1] ?? f;
      const date = /^- (?:Date|\uB0A0\uC9DC):\s*(\S+)/m.exec(text)?.[1] ?? statSync(join(dir, f)).mtime.toISOString().slice(0, 10);
      return { file: f, title, date };
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
    const secret = b64(crypto.getRandomValues(new Uint8Array(32)));
    const { token } = await derive(secret);
    const accessHash = createHash("sha256").update(token).digest("hex");
    const response = await fetch(`${server}/api/teams`, {
      method: "POST",
      redirect: "manual",
      headers: { ...accessHeaders(), "content-type": "application/json" },
      body: JSON.stringify({ accessHash }),
    });
    if (response.status !== 201) throw new Error(`Beaket answered ${response.status}: ${(await response.text()).slice(0, 300)}`);
    const { team } = await response.json();
    const config = { server, team, secret, cursor: 0 };
    writeConfig(config);
    console.log(`Made a team. Give this join code to your teammates, privately; anyone with it can read the team's records:\n\n${joinCode(config)}\n`);
  } else if (cmd === "team" && sub === "join") {
    const code = rest[0];
    if (!code?.startsWith("bkt1.")) throw new Error("A join code starts with bkt1.");
    const { server, team, secret } = JSON.parse(dec.decode(Buffer.from(code.slice(5), "base64url")));
    const existing = readConfig();
    if (existing && existing.team !== team) throw new Error(`This machine is already in another team (${CONFIG}). Remove that file first to join this one.`);
    const { changed, dir } = await pull({ server, team, secret, cursor: existing?.cursor ?? 0 });
    console.log(`Joined the team. ${changed} record(s) in ${dir}.`);
  } else if (cmd === "team" && sub === "show") {
    console.log(joinCode(needTeam()));
  } else if (cmd === "status") {
    const config = needTeam();
    console.log(`Team ${config.team} at ${config.server}. Records: ${cacheDir(config)}. Script: ${self}`);
  } else if (cmd === "push") {
    const config = needTeam();
    for (const file of [sub, ...rest].filter(Boolean)) {
      const { id, text } = recordId(file);
      const { seq } = await call(config, "PUT", `/api/teams/${config.team}/records/${id}`, await seal(config, id, basename(file), text));
      console.log(`Shared ${file} (record ${id}, change ${seq}).`);
    }
    await pull(config);
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
      console.log(`Could not reach Beaket (${error.message}). The records of the last pull are in ${cacheDir(config)}.`);
    }
  } else if (cmd === "index") {
    const config = needTeam();
    for (const r of index(config)) console.log(`- ${r.title} (${r.date}) — ${r.file}`);
  } else if (cmd === "session-start") {
    const config = readConfig();
    if (!config) process.exit(0);
    let note = "";
    try {
      await pull(config, HOOK_TIMEOUT_MS);
    } catch {
      note = " (Beaket could not be reached; these are from the last pull)";
    }
    const list = index(config);
    if (list.length === 0) process.exit(0);
    console.log(
      [
        `Your team's decision records (Beaket)${note}, newest first, in ${cacheDir(config)}:`,
        ...list.map((r) => `- ${r.title} (${r.date}) — ${r.file}`),
        "Before changing something one of them covers, read that record and follow it, or ask the person whether it should change.",
        `To share a new record: node ${self} push <file>.`,
      ].join("\n"),
    );
  } else {
    console.log(readFileSync(self, "utf8").split("\n").slice(1, 14).map((l) => l.replace(/^\/\/ ?/, "")).join("\n"));
  }
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
