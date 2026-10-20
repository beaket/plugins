# Beaket plugins

Claude Code plugins by Beaket.

## beaket
Name a decision you must make, and it reads what your team wrote about it in Slack, Jira, Confluence, Notion, Google Meet notes and GitHub, and gives you one page with only what the decision needs: the options, what is agreed, what is open, what nobody knows, what keeps being argued, and what the decision leans on, each line linked to its source. Everything is read on your machine, through the connectors your Claude Code already has, with your own access. Nothing is sent to Beaket.

### Install
In Claude Code:
```
/plugin marketplace add beaket/plugins
/plugin install beaket@beaket
```
Connect Slack, Atlassian, Notion and Google Drive first (`/mcp`). Then, for example:
```
주문 이벤트 파이프라인을 Kafka(MSK)로 갈지 SQS/SNS + EventBridge로 갈지 정해야 해. 결정에 필요한 것만 정리해 줘.
```
