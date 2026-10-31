# beaket

Cut the context of one decision down to what it needs, keep the decision as a record, and share records with your team end-to-end encrypted.

## Skills
- **decision-brief**: name a decision you must make; it reads Slack, Jira, Confluence, Notion, Google Meet notes and GitHub through your own connectors and gives you one page, each line linked to its source.
- **decision-record**: say what you chose, why and who you talked with; it drafts the record from the brief, you confirm, and it writes `decisions/<date>-<slug>.md`.
- **team**: make or join a Beaket team, invite someone, share or withdraw records, see the passports, and answer what leaves your machine.

## Install
In Claude Code 2.1.275 or later:
```
/plugin install beaket --marketplace beaket/plugins
```
In earlier versions, `/plugin marketplace add beaket/plugins`, then `/plugin install beaket@beaket`.

## Beta
Teams are made on `stg.beaket.com`, Beaket's beta server. Beaket will run on `beaket.com` later. Set another server with `team create --server <URL>` or `BEAKET_URL`.

## What leaves your machine
- **Your sources.** The skills read them through the connectors your Claude Code already has, with your own access. What they read goes to the model as in any Claude Code session. The plugin sends none of it to Beaket; it has no connector or server of its own for sources.
- **Your records, only in a team, only when you confirm.** `bin/beaket.mjs`, of which each skill carries a copy in its `scripts/`, encrypts a record on your machine before it leaves:
  - The team key (32 random bytes) is made on a member's machine and never leaves members' machines unwrapped. `hkdfKey` turns it, through HKDF-SHA-256, into a key for records, one for member cards and one for the previous team key.
  - `sealRecord`: the file name and text are encrypted with AES-256-GCM and a random nonce, bound to the team, the record id and the key's epoch.
  - Beaket receives only that ciphertext, the nonce and the epoch.
- **Your own key.** Each member has an X25519 key pair and an access token, made on their machine (`keyPair`). Beaket receives the public key and the SHA-256 of the token. The team key reaches you wrapped to your public key (`wrap`); only your private key opens it (`unwrap`).
- **Invites.** `team invite` makes a secret that lets one person join, once, within a day. Beaket keeps the hash of the token it yields and the team key sealed with it. The code goes on your clipboard and in `~/.config/beaket/join-code`, and is never printed unless you ask with `--print`, so it stays out of your AI assistant's conversation, which is sent to its model. Only a manager invites.
- **Removing someone.** `team remove <name>` (managers only): Beaket refuses that member from then on, and a new team key, wrapped only to those who stay, encrypts every record pushed afterwards. Invites not yet used are cancelled. The member removed keeps the copies they already pulled.
- **Each record's passport, in the clear.** Beside the ciphertext, `push` sends what `passportOf` reads from the record's own lines: its `Label:` (two or three words; without one, the words of the file name), the name on `Decided by:`, its `Date:` and `Review by:`, and the links under Sources, Rests on and Supersedes. Nothing of the Decision, Why, Talked with or Rejected. `answer <file> question|unchanged|changed` adds who answered, what and when to the passport and moves its state (valid, questioned, changed; withdrawn with the record); it sends none of the words. The passport is what a member's session, the map and other vendors' AIs read about a decision without its text (docs/specs/passport.md in beaket/beaket). `passports` prints them as Beaket holds them.
- **Read keys for other AIs.** A manager can make a read key (`team reader`) for another vendor's AI (Rovo, a Notion agent, Cursor, another Claude Code). It reaches only the window, an MCP server at `<server>/api/teams/<team>/mcp`, which answers with passports and links and never a record's text, and can change nothing. Beaket keeps the SHA-256 of its token and logs each call by tool, never the words asked. The key goes on your clipboard and into `~/.config/beaket/reader-key`, and is printed only with `--print`. `team readers` lists them, `team revoke-reader <id>` revokes one at once.
- **What Beaket sees:** the team's id, each member's random id, role, public key and when they joined or were removed, each record's random id, size, key epoch and when it changed, each record's passport (above), and a log of which member id joined, shared, pulled, withdrew, answered or removed what, and when; like any web server, the IP address of each call. Not members' names (each member's name is on a card sealed with the team key), a record's title, text or file name, a team key or a private key. The passport's owner is the name written on the record's Decided by line, and its label is the one line of wording Beaket holds.
- **The log.** `team log` shows every member that log with names, which only the team can read.
- **On your machine:** your private key, token and the team keys in `~/.config/beaket/team.json` (readable only by you), decrypted records as plain files in `~/.cache/beaket/teams/<team>/`, and private records in `~/.config/beaket/private/`.
- **You do not have to trust Beaket's server** to keep records secret: it never receives a team key. You rely on it to refuse a removed member the records pushed before their removal.
- **Private records** carry `<!-- beaket-private -->` and `push` refuses them.

This script is the whole client: what leaves your machine for Beaket is what it sends, and you can read it. Each skill carries a copy of it in its `scripts/`, so that every tool finds it; `node bin/beaket.mjs verify` shows that all copies are the same.
