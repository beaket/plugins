# beaket

Cut the context of one decision down to what it needs, keep the decision as a record, and share records with your team end-to-end encrypted.

## Skills
- **decision-brief**: name a decision you must make; it reads Slack, Jira, Confluence, Notion, Google Meet notes and GitHub through your own connectors and gives you one page, each line linked to its source.
- **decision-record**: say what you chose, why and who you talked with; it drafts the record from the brief, you confirm, and it writes `decisions/<date>-<slug>.md`.
- **team**: make or join a Beaket team, invite someone, share or withdraw records, and answer what leaves your machine.

## What leaves your machine
- **Your sources.** The skills read them through the connectors your Claude Code already has, with your own access. What they read goes to the model as in any Claude Code session. The plugin sends none of it to Beaket; it has no connector or server of its own for sources.
- **Your records, only in a team, only when you confirm.** `bin/beaket.mjs` encrypts a record on your machine before it leaves:
  - `derive`: the team secret (32 random bytes, in the join code) gives, through HKDF-SHA-256, an access token and an AES-256-GCM key.
  - `seal`: the file name and text are encrypted with that key and a random nonce, bound to the team and record id.
  - `call`: Beaket receives the access token, the nonce and the ciphertext. When the team is made, it receives only the SHA-256 of the token.
- **What Beaket sees:** the team's id, each record's random id, its size, when it changed and the order of changes, and, like any web server, the IP address of each call. Not titles, text, file names, the secret or the key, and no name or account.
- **On your machine:** the join code's secret in `~/.config/beaket/team.json` (readable only by you), decrypted records as plain files in `~/.cache/beaket/teams/<team>/`, and private records in `~/.config/beaket/private/`.
- **Who can read:** whoever has the join code. Pass it privately. A member cannot be removed; make a new team and give the rest a new code.
- **Private records** carry `<!-- beaket-private -->` and `push` refuses them.

This script is the whole client: what leaves your machine for Beaket is what it sends, and you can read it.
