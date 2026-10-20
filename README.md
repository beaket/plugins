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
