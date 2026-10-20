#!/usr/bin/env node
// Beaket team records: share decision records with your team, end-to-end encrypted.
// Beaket keeps them as ciphertext and never receives the key.
//
//   node beaket.mjs team create [--server URL]   make a team; its join code goes to the clipboard and a private file
//   node beaket.mjs team join [--file F | code]  join a team with a code from a teammate, read from the clipboard by default
//   node beaket.mjs team rotate                  remove members: move every record to a new team with a new key and code
//   node beaket.mjs team show [--print]          put this team's join code on the clipboard again, to invite someone
//
// The join code holds the team's key. It never goes to standard output unless you ask with --print,
// so that it stays out of an AI assistant's conversation, which is sent to its model.
// The default server, stg.beaket.com, is Beaket's beta; Beaket will run on beaket.com later.
//   node beaket.mjs status                       is this machine in a team, and where are its records
//   node beaket.mjs paths                        the config, cache and private folders of this machine
//   node beaket.mjs push <file>...               encrypt and share decision records (never one marked private)
//   node beaket.mjs unshared [folder]            list the records in decisions/ not yet shared, and the private ones
//   node beaket.mjs remove <file>                withdraw a shared record
//   node beaket.mjs pull                         fetch and decrypt the team's records
//   node beaket.mjs index                        list the team's newest records
//   node beaket.mjs session-start                for the SessionStart hook: pull, then print the index
import { webcrypto as crypto, createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_SERVER = "https://stg.beaket.com";
const onBeta = (server) => (server === DEFAULT_SERVER ? ` It is Beaket's beta server; Beaket will run on beaket.com later.` : "");
const HOOK_TIMEOUT_MS = 3000;
const INDEX_SIZE = 30;
const CONFIG_DIR = process.env.BEAKET_CONFIG_DIR ?? join(homedir(), ".config", "beaket");
const CONFIG = join(CONFIG_DIR, "team.json");
const CACHE_ROOT = process.env.BEAKET_CACHE_DIR ?? join(homedir(), ".cache", "beaket", "teams");
const JOIN_FILE = join(CONFIG_DIR, "join-code");
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

// Keep the join code in a file only its owner can read, and on the clipboard; print it only on request.
function handOut(config, print) {
  const code = joinCode(config);
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(JOIN_FILE, code + "\n", { mode: 0o600 });
  chmodSync(JOIN_FILE, 0o600);
  if (print) return code;
  const copied = toClipboard(code);
  return `The join code is ${copied ? "on your clipboard and " : ""}in ${JOIN_FILE} (readable only by you). Paste it to each teammate in a private message; whoever holds it can read every record of the team. Do not paste it into an AI assistant: they join with \`team join\`, which reads it from their clipboard.`;
}

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

async function makeTeam(server) {
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
  return { server, team, secret, cursor: 0 };
}

const [cmd, sub, ...rest] = process.argv.slice(2);
const self = fileURLToPath(import.meta.url);

try {
  if (cmd === "team" && sub === "create") {
    if (readConfig()) throw new Error(`This machine is already in a team (${CONFIG}). Remove that file first to make another.`);
    const at = rest.indexOf("--server");
    const server = (at >= 0 ? rest[at + 1] : process.env.BEAKET_URL ?? DEFAULT_SERVER).replace(/\/+$/, "");
    const config = await makeTeam(server);
    writeConfig(config);
    console.log(`Made a team at ${server}.${onBeta(server)} ${handOut(config, rest.includes("--print"))}`);
  } else if (cmd === "team" && sub === "join") {
    const at = rest.indexOf("--file");
    const code = (at >= 0 ? readFileSync(rest[at + 1], "utf8") : rest[0] ?? fromClipboard()).trim();
    if (!code.startsWith("bkt1.")) throw new Error("No join code found: copy the code your teammate sent (it starts with bkt1.) and run this again, or pass --file <file holding it>.");
    const { server, team, secret } = JSON.parse(dec.decode(Buffer.from(code.slice(5), "base64url")));
    const existing = readConfig();
    if (existing && existing.team !== team && existing.server === server && !rest.includes("--switch"))
      throw new Error(`This machine is already in another team (${CONFIG}). If the team moved to a new code (team rotate), run this again with --switch.`);
    if (existing && existing.team !== team) rmSync(cacheDir(existing), { recursive: true, force: true });
    const { changed, dir } = await pull({ server, team, secret, cursor: existing?.team === team ? existing.cursor : 0 });
    console.log(`Joined the team at ${server}.${onBeta(server)} ${changed} change(s) pulled; the records are in ${dir}.`);
  } else if (cmd === "team" && sub === "rotate") {
    // To remove someone: a new team with a new key gets every record, and the old team is emptied.
    const old = needTeam();
    await pull(old);
    const files = readdirSync(cacheDir(old)).filter((f) => f.endsWith(".md"));
    const fresh = await makeTeam(old.server);
    for (const f of files) {
      const text = readFileSync(join(cacheDir(old), f), "utf8");
      const id = ID_LINE.exec(text)?.[1];
      if (id) await call(fresh, "PUT", `/api/teams/${fresh.team}/records/${id}`, await seal(fresh, id, f, text));
    }
    for (const f of files) {
      const id = ID_LINE.exec(readFileSync(join(cacheDir(old), f), "utf8"))?.[1];
      if (id) await call(old, "DELETE", `/api/teams/${old.team}/records/${id}`);
    }
    rmSync(cacheDir(old), { recursive: true, force: true });
    writeConfig(fresh);
    await pull(readConfig());
    console.log(
      `Moved ${files.length} record(s) to a new team at ${fresh.server} and emptied the old one; its join code no longer reaches them, ` +
        `though whoever pulled them before keeps their copies. ${handOut(fresh, rest.includes("--print"))} Give it only to the members who stay; each runs \`team join\` again.`,
    );
  } else if (cmd === "team" && sub === "show") {
    console.log(handOut(needTeam(), rest.includes("--print")));
  } else if (cmd === "status") {
    const config = needTeam();
    console.log(`Team ${config.team} at ${config.server}.${onBeta(config.server)} Records: ${cacheDir(config)}. Script: ${self}`);
  } else if (cmd === "push") {
    const config = needTeam();
    for (const file of [sub, ...rest].filter(Boolean)) {
      const { id, text } = recordId(file);
      const { seq } = await call(config, "PUT", `/api/teams/${config.team}/records/${id}`, await seal(config, id, basename(file), text));
      console.log(`Shared ${file} (record ${id}, change ${seq}).`);
    }
    await pull(config);
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
        "Before changing something one of them covers, read that record and follow it, or ask the person whether it should change. Cite a record by its title, its date and its file name (with its path under decisions/ when the repository has it), never as \"today\" or by a cache path alone. When a request goes against a record, say so in a few lines before doing anything: the record's title, date and file name, the decision, and the reason in the decider's words with who they talked with, with the record's source links; then ask. When a request follows a record, mention it in one line at most. Mark anything not from a record or the team's sources as your own general knowledge, and before citing a document as current, check it is not superseded or from a cancelled project.",
        `To share a new record: node ${self} push <file>.`,
      ].join("\n"),
    );
  } else {
    const lines = readFileSync(self, "utf8").split("\n").slice(1);
    console.log(lines.slice(0, lines.findIndex((l) => !l.startsWith("//"))).map((l) => l.replace(/^\/\/ ?/, "")).join("\n"));
  }
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
