---
name: team
description: Set up and explain the person's Beaket team, which shares decision records end-to-end encrypted. Use when the person asks to share decision records with teammates, to make or join a Beaket team, to invite someone, to share or withdraw a record, or asks where records go, who can read them, whether Beaket can read them, or what leaves their machine when they use this plugin (for example "make a beaket team", "share our decisions with Priya", "can Beaket see our records?", "what leaves my machine?"), in any language.
---

# Beaket team

A Beaket team shares decision records among its members. A record is encrypted on the member's machine with a key only the team has, and Beaket keeps the ciphertext. Your job is to set the team up, share only what the person chose, and answer questions about it from the code, not from memory.

The script is `node <plugin>/bin/beaket.mjs`, where the plugin folder is two levels above this skill's base directory. Use that path in every command and show it to the person when they ask.

## Rules
- Share a record only when the person said to, by name or as a list they confirmed. Never share a record marked `<!-- beaket-private -->`, one the person said to keep to themselves, or one holding something they said not to share; the script refuses the marked ones.
- The join code gives anyone holding it every record of the team. Show it only to the person, and tell them to pass it privately. Never put it in a file, a commit, a message or a record.
- Answer what Beaket stores or can read only from the plugin's code and README, quoting the lines, and say what you could not check.

## What leaves the machine
When the person asks, read `<plugin>/bin/beaket.mjs` and `<plugin>/README.md` and show them:
- The decision-brief and decision-record skills read sources through the person's own connectors. What they read goes to the model as in any Claude Code session; the plugin sends none of it to Beaket and has no connector or server of its own for sources.
- In a team, a record goes to Beaket only through `push`, encrypted first: `derive` turns the team secret into an access token and an AES-256-GCM key with HKDF, `seal` encrypts the file name and text, and `call` sends only the token, the nonce and the ciphertext. Beaket receives the SHA-256 of the token when the team is made (`team create`), never the secret or the key.
- Beaket sees the team's id, each record's random id, its size, when it changed, and the order of changes. It does not see titles, text or file names, and it keeps no name or account of who pushed; like any web server, it sees the IP address of each call.
- The secret is in the config file named by `status` (`team.json`, readable only by its owner), and decrypted records are plain files in the cache folder `pull` names.
- Removing a member is not possible: make a new team and give the rest a new code.

## Steps
1. **Where they are.** Run `status`. It fails when this machine is in no team.
2. **Make a team** (`team create`) when they ask for one and are in none. Print the join code for them only, and say that whoever holds it can read every record of the team, so it goes to each teammate in a private message, and each runs `team join <code>` (or asks Claude to). A team has no name on Beaket; if they give one, say so.
3. **Join a team** (`team join <code>`) with a code they paste.
4. **Invite someone** (`team show`): print the code, with the same warning.
5. **Share what is already written.** After making or joining a team, or when asked, run `unshared` in the repository root (or with the folder the person named). It lists each record as shared, not shared or private. Show the not-shared ones by title and ask which to share; share only those (`push <file>...`). Mention the private ones as staying on this machine.
6. **Withdraw a record** (`remove <file>`): it disappears from every member's next pull. Say that members who already pulled it had a copy.
7. Say what you ran and what changed, in one or two lines.
