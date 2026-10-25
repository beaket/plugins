# Beaket plugins

Claude Code plugins by Beaket.

## beaket
Two skills that feed each other.

**decision-brief.** Name a decision you must make, and it reads what your team wrote about it in Slack, Jira, Confluence, Notion, Google Meet notes and GitHub, and gives you one page with only what the decision needs: the options, what is agreed, what is open, what nobody knows, what keeps being argued, and what the decision leans on, each line linked to its source. Everything is read on your machine, through the connectors your Claude Code already has, with your own access. Nothing is sent to Beaket.

**decision-record.** When you decide, say what you chose, why, and who you talked with. It drafts the rest from the brief, you confirm, and it writes one file to `decisions/` in your repository. Commit it and your team can read it; the next brief finds it.

### Install
In Claude Code:
```
/plugin marketplace add beaket/plugins
/plugin install beaket@beaket
```
Connect Slack, Atlassian, Notion and Google Drive first (`/mcp`). Then, for example:
```
We need to decide whether the order event pipeline goes to Kafka (MSK) or to SQS/SNS with EventBridge. Give me only what the decision needs.
```

### Share records with your team, end-to-end encrypted
Ask Claude to make a Beaket team (the **team** skill), then to invite each teammate. Each invite goes on your clipboard and works for one person, once, within a day; send it privately, and they copy it and ask Claude to join. From then on a record you confirm is encrypted on your machine and shared; Beaket keeps it but cannot read it, because the team's key never leaves your team's machines. A manager can remove one member, and every member can see who joined, shared, pulled and removed what. Every brief and every new Claude Code session of a member reads the team's records first. A record you keep to yourself is never shared.

What leaves your machine, line by line: [plugins/beaket/README.md](plugins/beaket/README.md).
