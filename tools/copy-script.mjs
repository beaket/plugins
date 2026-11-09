#!/usr/bin/env node
// Copy plugins/beaket/bin/beaket.mjs into each skill's scripts/, so that a skill finds its script in its
// own folder in every tool (Claude Code, GitHub Copilot, Codex), and write the script's plain-words rules (PLAIN_WORDS)
// into the decision-brief skill between its plain-words markers, since that skill runs apart from the session that
// is given them (beaket/beaket#3189). With --page, also write the term table (TERMS) as JSON to the page's copy in
// beaket/beaket, so that the page names each thing as the plugin does (beaket/beaket#3194). With --check, only say
// which copy differs.
//
//   node tools/copy-script.mjs [--check] [--page <beaket repo>/app/page/terms.json]
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const plugin = join(dirname(fileURLToPath(import.meta.url)), "..", "plugins", "beaket");
const source = join(plugin, "bin", "beaket.mjs");
const text = readFileSync(source, "utf8");
const check = process.argv.includes("--check");
let stale = 0;
for (const skill of readdirSync(join(plugin, "skills"))) {
  const copy = join(plugin, "skills", skill, "scripts", "beaket.mjs");
  if (existsSync(copy) && readFileSync(copy, "utf8") === text) continue;
  if (check) {
    console.error(`${copy} differs from ${source}`);
    stale++;
  } else {
    mkdirSync(dirname(copy), { recursive: true });
    copyFileSync(source, copy);
    console.log(`copied to ${copy}`);
  }
}

// The plain-words rules, as the script prints them: PLAIN_WORDS, with its names taken from TERMS.
const plain = execFileSync(process.execPath, [source, "plain-words", "--print"], { encoding: "utf8" }).trimEnd();
const brief = join(plugin, "skills", "decision-brief", "SKILL.md");
const skill = readFileSync(brief, "utf8");
const START = "<!-- plain-words: written by tools/copy-script.mjs from PLAIN_WORDS in bin/beaket.mjs; change it there -->";
const END = "<!-- /plain-words -->";
const at = skill.indexOf(START);
const end = skill.indexOf(END);
if (at < 0 || end < at) throw new Error(`${brief} has no ${START} … ${END} markers`);
const fresh = `${skill.slice(0, at + START.length)}\n${plain}\n${skill.slice(end)}`;
if (fresh !== skill) {
  if (check) {
    console.error(`${brief}: its plain-words rules differ from PLAIN_WORDS in ${source}`);
    stale++;
  } else {
    writeFileSync(brief, fresh);
    console.log(`wrote the plain-words rules into ${brief}`);
  }
}
// The term table, the JSON object TERMS in the script, read here without running the script.
const at2 = process.argv.indexOf("--page");
if (at2 >= 0) {
  const page = process.argv[at2 + 1];
  const table = /^const TERMS = (\{[\s\S]*?\n\});$/m.exec(text);
  if (!page || !table) throw new Error(page ? `${source} has no TERMS object` : "--page takes the page's terms.json");
  const json = `${JSON.stringify(JSON.parse(table[1]), null, 2)}\n`;
  if (existsSync(page) && readFileSync(page, "utf8") === json) {
    // the same
  } else if (check) {
    console.error(`${page} differs from TERMS in ${source}`);
    stale++;
  } else {
    writeFileSync(page, json);
    console.log(`wrote the term table to ${page}`);
  }
}
process.exit(stale ? 1 : 0);
