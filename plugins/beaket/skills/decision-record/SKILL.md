---
name: decision-record
description: Keep a decision the person has just made as a record their team can read later: what was chosen, why, who decided and who was consulted, what was rejected, what is still open, and the sources. Use when the person says what they decided (for example "we're going with SQS", "decided: Kafka, after talking with the platform lead", "record this decision"), in any language, above all after a decision brief.
---

# Decision record

What decides a decision is often never written down: a talk with someone, a table someone made. Your job is to keep it, with almost no work from the person. They say one line; you draft the rest from what this conversation already has, they confirm, and you write one file.

## Rules
- The reason is the person's. Never invent a reason or a person. Take the reason only from what the person said, and the options, trade-offs and links only from the brief or the sources in this conversation.
- Write only inside the decisions folder. Never write, post or comment anywhere else. Send the record nowhere but to the person's Beaket team, encrypted by the plugin, and only after they confirm.
- Write the record, its headings included, and every reply in the language the person wrote in.
- The plugin's script is `<skill>/scripts/beaket.mjs`, where `<skill>` is this skill's folder. Run the script on its own, never chained with other commands by `;`, `&&` or `|` nor run from another folder with `cd`, so that a permission that allows the script covers it.

## Steps
1. **What you have.** The decision brief in this conversation, if there is one, and what the person just said. With no brief here, find the documents, issues and threads the person's words refer to (the options, numbers and people they named) in the sources and the decision records, so that Rejected, Constraints, Still open and Sources can be linked. Search with the subject being decided (for example ingress, order events), not only the options' names: a constraint (a deadline, a freeze, an audit, a security or legal rule) is often written without any option's name. Open the decision's issue and every issue it links: an agreement made in a linked issue often binds how the decision is carried out.
2. **Ask once, only for what is missing.** The record needs: the option chosen, why in the person's words, and who they talked with. The decider is the person unless they name someone else; do not ask for it. If the choice, the reason or the people are missing, ask for all the missing ones in one short question, and never ask again for what they already said. Do not ask for anything else.
3. **Draft**, leaving out a section with nothing in it:

```
# <the decision, one line>

- Date: <today>
- Decided by: <who>
- Status: decided

## Decision
<the option chosen, one or two lines>

## Why
<the person's reason, in their words>

## Talked with
- <who>: <what they said that mattered, in the person's words>

## Rejected
- <option> — <why, from the person or from the trade-offs in the brief> [link]

## Constraints
- <what binds carrying out this decision, set or agreed elsewhere: a deadline, a freeze, a rule from a linked issue; never the details of another decision> [link]

## Still open
- <what the brief left open that this decision does not settle> [link]

## Revisit when
- <what the person said would reopen this>

## Sources
- <the documents and threads the decision leans on> [link]
```

Under Why and Talked with, write only what the person said; a fact from the sources that also argues against an option goes under Rejected with its link, never under Why as their reason. Under Rejected, Constraints, Still open and Sources, write only what the brief or the sources hold, with their links. A line taken only from AI meeting notes (Gemini and the like), a vendor or one person's remark is marked as such (for example "(Gemini notes, not in the transcript)"); check AI notes against the transcript first, and leave out what the transcript contradicts. Still open holds questions about the decision itself, never a constraint already set (that goes under Constraints) nor gaps of your tools (an issue that would not open, a search that failed). A number or fact the person gave stays theirs under Why; link a source next to it only when that source holds the same number, and never one that does not. Write every number with its unit, and every person by the full name the sources give them, with their role the first time.
4. **Confirm.** Check whether the person is in a Beaket team: `node <skill>/scripts/beaket.mjs status` (`<skill>` is this skill's folder, the one that holds this SKILL.md), run alone, prints the team when they are and "This machine is in no Beaket team" when they are not. Show the draft and ask one question only: whether to keep it, and, if they are in a team, to share it with the team. Everything else you need them to see goes in short statements around the draft, not in further questions: the lines marked as AI notes or one person's remark, for them to check; if they said nothing of when or why it would be looked at again, that they can add what would reopen it; if they did (for example "we look at it again in 2027"), that is Revisit when. Never put a placeholder such as "(to confirm)" in a draft: leave the section out. Change what they correct and nothing else: the file you write is the draft you showed, word for word, with only their corrections applied; keep the tone, the sections and every other word, role and number as they were. Remove or reword a line they did not correct, a Still open item above all, only when they say so; when something they said seems to settle it, keep it and say in the same answer that it stays unless they say to remove it.
   If the person wants something kept from the team (a staffing call, something personal, "only I should know"), it is private: write no part of it (the person, the change or the reason) into the repository, into an existing record or into the team's records, where a commit or a push would share it. Write nothing until you ask, in one line, whether to keep it at all (the default is no); if they do, write it to the private folder that `node <skill>/scripts/beaket.mjs paths` names, with `<!-- beaket-private -->` as its first line, and say where it is.
5. **Write** it to `decisions/<YYYY-MM-DD>-<short-slug>.md` at the root of the current git repository (or of the current folder outside one), or to the folder the person named. If a record of the same decision is there, update it and note the change under a `## Changes` heading as `- <YYYY-MM-DD> <who changed it>: <what changed>`, instead of writing a second file.
6. If they are in a team and agreed to share, or the record was already shared (its first line is `<!-- beaket-record: ... -->`) and they confirmed the change, run `node <skill>/scripts/beaket.mjs push <file>`. It encrypts the record on this machine; Beaket keeps it but cannot read it, and every member's next brief and session reads it.
7. Say where it was written and whether it was shared. If they are in no team, say in one line that they can ask to make a Beaket team to share records with teammates, end-to-end encrypted.
