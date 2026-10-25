---
name: team
description: Set up and explain the person's Beaket team, which shares decision records end-to-end encrypted. Use when the person asks to share decision records with teammates, to make or join a Beaket team, to invite or remove someone, to see who is in the team or who did what, to share or withdraw a record, to add a question to a record, or asks where records go, who can read them, whether Beaket can read them, or what leaves their machine when they use this plugin (for example "make a beaket team", "share our decisions with Priya", "can Beaket see our records?", "what leaves my machine?"), in any language.
---

# Beaket team

A Beaket team shares decision records among its members. A record is encrypted on the member's machine with a key only the team has, and Beaket keeps the ciphertext. Each member has their own key; managers invite and remove members. Your job is to set the team up, share only what the person chose, and answer questions about it from the code, not from memory.

The script is `node <skill>/scripts/beaket.mjs`, where `<skill>` is this skill's folder, the one that holds this SKILL.md. Use that path in every command and show it to the person when they ask.

## Rules
- Share a record only when the person said to, by name or as a list they confirmed. Never share a record marked `<!-- beaket-private -->`, one the person said to keep to themselves, or one holding something they said not to share; the script refuses the marked ones.
- An invite code opens the team's key for one person, once, within a day. Keep it out of this conversation, which goes to the model: never run `team invite --print`, never read `team.json` or the `join-code` file, and never ask the person to paste a code here. The script puts it on their clipboard and in a file only they can read; they send it to that one person in a private message. If they paste one here anyway, use it, and say in one line that it went to the model and next time they only need to copy it.
- Answer what Beaket stores or can read only from the plugin's code and README, quoting the lines, and say what you could not check.

## What leaves the machine
When the person asks, read `<skill>/scripts/beaket.mjs`, which is the whole client, and show them:
- The decision-brief and decision-record skills read sources through the person's own connectors. What they read goes to the model as in any Claude Code session; the plugin sends none of it to Beaket and has no connector or server of its own for sources.
- In a team, a record goes to Beaket only through `push`, encrypted first with the team key (`sealRecord`); Beaket receives the ciphertext, the nonce and the key's epoch. Each member has their own X25519 key pair and token (`keyPair`); Beaket receives the public key and the SHA-256 of the token, and the team key only wrapped to each member's public key (`wrap`).
- Beaket sees the team's id, each member's random id, role, public key and dates, each record's random id, size, epoch and when it changed, and a log of which member id joined, shared, pulled, withdrew or removed what; like any web server, it sees the IP address of each call. It does not see names (sealed on each member's card), titles, text, file names or any key.
- Each person's private key, token and the team keys are in `team.json`, and an invite code in `join-code`, both in the config folder `paths` names and readable only by their owner; decrypted records are plain files in the cache folder `pull` names.
- Removing a member (`team remove`): Beaket refuses them at once, and records pushed afterwards use a new key that only those who stay have; the person removed keeps the copies they already pulled. For the records pushed before, the team relies on Beaket's refusal.
- The server: `stg.beaket.com` is Beaket's beta server, and Beaket will run on beaket.com later. Neither the plugin nor its README says how long the beta keeps records or whether beta teams move to beaket.com; say that you could not find it rather than guess.

## Steps
1. **Where they are.** Run `status`. It fails when this machine is in no team.
2. **Make a team** (`team create`) when they ask for one and are in none; they become its manager. It shows the server it used; if it is not the one they expect, say so. If it is `stg.beaket.com`, say in one line that it is Beaket's beta server and that Beaket will run on beaket.com later. A team has no name on Beaket; if they give one, say so.
3. **Invite someone** (`team invite`, or `team invite --manager` for someone who will also invite and remove): one invite per person. Tell them the code is on their clipboard and in the file the script names, that it lets one person join, once, within a day, and that they send it to that person in a private message; that person copies it and asks Claude to join. Only a manager can invite; if the script says so, tell them to ask a manager.
4. **Join a team**: ask them to copy the code their teammate sent, then run `team join`, which reads it from the clipboard (or `team join --file <file>` if they saved it to a file). If this machine is in another team, say so and add `--switch` only after they confirm leaving it. A code starting with `bkt1.` is from the old shared-code teams: they need a new invite.
5. **Share what is already written.** After making or joining a team, or when asked, run `unshared` in the repository root (or with the folder the person named). It lists each record as shared, not shared or private. Show the not-shared ones by title and ask which to share; share only those (`push <file>...`). Mention the private ones as staying on this machine.
6. **Withdraw a record** (`remove <file>`): it disappears from every member's next pull. Say that members who already pulled it had a copy.
7. **Who is in the team, and who did what**: `team members` lists names, roles and dates; `team log` shows who joined, shared, pulled, withdrew and removed what, and when (`--all` for all of it). Show what they asked about, not the whole log. A member whose card does not match its key is marked by the script; say so plainly.
8. **Remove a member** (someone left, or their laptop was lost): confirm the name with them, then run `team remove <name>` (managers only). Say that Beaket refuses that person from now on, that records shared from now on use a new key they do not have, that unused invites were cancelled, and that they keep the copies they already pulled. Nobody else needs to do anything.
9. **Add a question to a record**, someone else's included, when the person wants a question kept with it (for example "note my question so it comes up when this is revisited"): show the line, then after they confirm, append `- <YYYY-MM-DD> <their name>: <question>` under a `## Questions` heading at the end of the record's file (in `decisions/`, or in the team's cache folder for a record only the team has), change nothing else in it, and `push` that file.
10. Say what you ran and what changed, in one or two lines.
