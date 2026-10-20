---
name: team
description: Set up and explain the person's Beaket team, which shares decision records end-to-end encrypted. Use when the person asks to share decision records with teammates, to make or join a Beaket team, to invite or remove someone, to share or withdraw a record, to add a question to a record, or asks where records go, who can read them, whether Beaket can read them, or what leaves their machine when they use this plugin (for example "make a beaket team", "share our decisions with Priya", "can Beaket see our records?", "what leaves my machine?"), in any language.
---

# Beaket team

A Beaket team shares decision records among its members. A record is encrypted on the member's machine with a key only the team has, and Beaket keeps the ciphertext. Your job is to set the team up, share only what the person chose, and answer questions about it from the code, not from memory.

The script is `node <plugin>/bin/beaket.mjs`, where the plugin folder is two levels above this skill's base directory. Use that path in every command and show it to the person when they ask.

## Rules
- Share a record only when the person said to, by name or as a list they confirmed. Never share a record marked `<!-- beaket-private -->`, one the person said to keep to themselves, or one holding something they said not to share; the script refuses the marked ones.
- The join code holds the team's key, and gives anyone holding it every record of the team. Keep it out of this conversation, which goes to the model: never run `team show --print` or `team create --print`, never read `team.json` or the `join-code` file, and never ask the person to paste a code here. The script puts it on their clipboard and in a file only they can read; they pass it to each teammate in a private message. If they paste one here anyway, use it, and say in one line that it went to the model and next time they only need to copy it.
- Answer what Beaket stores or can read only from the plugin's code and README, quoting the lines, and say what you could not check.

## What leaves the machine
When the person asks, read `<plugin>/bin/beaket.mjs` and `<plugin>/README.md` and show them:
- The decision-brief and decision-record skills read sources through the person's own connectors. What they read goes to the model as in any Claude Code session; the plugin sends none of it to Beaket and has no connector or server of its own for sources.
- In a team, a record goes to Beaket only through `push`, encrypted first: `derive` turns the team secret into an access token and an AES-256-GCM key with HKDF, `seal` encrypts the file name and text, and `call` sends only the token, the nonce and the ciphertext. Beaket receives the SHA-256 of the token when the team is made (`team create`), never the secret or the key.
- Beaket sees the team's id, each record's random id, its size, when it changed, and the order of changes. It does not see titles, text or file names, and it keeps no name or account of who pushed; like any web server, it sees the IP address of each call.
- The secret is in `team.json` and the join code in `join-code`, both in the config folder `paths` names and readable only by their owner; decrypted records are plain files in the cache folder `pull` names. The script never prints the join code unless asked with `--print`, so that it stays out of an AI assistant's conversation.
- The server: `stg.beaket.com` is Beaket's beta server, and Beaket will run on beaket.com later. Neither the plugin nor its README says how long the beta keeps records or whether beta teams move to beaket.com; say that you could not find it rather than guess.
- Removing a member: `team rotate` moves every record to a new team with a new key and join code, and empties the old team, so the old code reaches nothing new; whoever pulled before keeps their copies. Beaket keeps no list of members and no log of who read what, because it knows no one.

## Steps
1. **Where they are.** Run `status`. It fails when this machine is in no team.
2. **Make a team** (`team create`) when they ask for one and are in none. It shows the server it used; if it is not the one they expect, say so. If it is `stg.beaket.com`, say in one line that it is Beaket's beta server and that Beaket will run on beaket.com later. Tell them where the join code is (their clipboard and the file the script names), that whoever holds it can read every record of the team, so it goes to each teammate in a private message, and that each teammate copies it and asks Claude to join. A team has no name on Beaket; if they give one, say so.
3. **Join a team**: ask them to copy the code their teammate sent, then run `team join`, which reads it from the clipboard (or `team join --file <file>` if they saved it to a file). If the team moved to a new code, add `--switch`.
4. **Invite someone** (`team show`): it puts the code on their clipboard again; give the same warning.
5. **Share what is already written.** After making or joining a team, or when asked, run `unshared` in the repository root (or with the folder the person named). It lists each record as shared, not shared or private. Show the not-shared ones by title and ask which to share; share only those (`push <file>...`). Mention the private ones as staying on this machine.
6. **Withdraw a record** (`remove <file>`): it disappears from every member's next pull. Say that members who already pulled it had a copy.
7. **Remove a member** (someone left, or a code leaked): run `team rotate`, then tell the person to give the new code only to those who stay, each of whom asks Claude to join with `team join --switch`. Say that the people removed keep the copies they already pulled.
8. **Add a question to a record**, someone else's included, when the person wants a question kept with it (for example "note my question so it comes up when this is revisited"): show the line, then after they confirm, append `- <YYYY-MM-DD> <their name>: <question>` under a `## Questions` heading at the end of the record's file (in `decisions/`, or in the team's cache folder for a record only the team has), change nothing else in it, and `push` that file.
9. Say what you ran and what changed, in one or two lines.
