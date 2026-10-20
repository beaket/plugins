# Beaket plugin

`decision-brief`: name a decision you must make, and it reads what your team wrote about it in Slack, Jira, Confluence, Notion, Google Meet notes and GitHub, and gives you one page with only what the decision needs. Everything is read on your machine, through the connectors your Claude Code already has, with your own access. Nothing is sent to Beaket.

`decision-record`: when you decide, say what you chose, why and who you talked with; it drafts the record from the brief, you confirm, and it writes `decisions/<date>-<slug>.md` in your repository, where the next brief finds it.

## Try it
```
claude --plugin-dir ./plugins/beaket
```
Then: `We need to decide whether the order event pipeline goes to Kafka (MSK) or to SQS/SNS with EventBridge. Give me only what the decision needs.`

Connect Slack, Atlassian, Notion and Google Drive in Claude Code first (`/mcp`); a source with no connection is listed under "Could not search".
