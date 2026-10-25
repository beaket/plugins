#!/usr/bin/env node
// Copy plugins/beaket/bin/beaket.mjs into each skill's scripts/, so that a skill finds its script in its
// own folder in every tool (Claude Code, GitHub Copilot, Codex). With --check, only say which copy differs.
//
//   node tools/copy-script.mjs [--check]
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync } from "node:fs";
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
process.exit(stale ? 1 : 0);
