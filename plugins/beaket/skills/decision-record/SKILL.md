---
name: decision-record
description: Keep a decision the person has just made as a record their team can read later: what was chosen, why, who decided and who was consulted, what was rejected, what is still open, and the sources. Use when the person says what they decided (for example "we're going with SQS", "decided: Kafka, after talking with the platform lead", "record this decision"), in any language, above all after a decision brief.
---

# Decision record

What decides a decision is often never written down: a talk with someone, a table someone made. Your job is to keep it, with almost no work from the person. They say one line; you draft the rest from what this conversation already has, they confirm, and you write one file.

## Rules
- The reason is the person's. Never invent a reason or a person. Take the reason only from what the person said, and the options, trade-offs and links only from the brief or the sources in this conversation.
- Write only inside the decisions folder. Never write, post or comment anywhere else, and send nothing anywhere.
- Write the record, its headings included, in the language the person wrote in.

## Steps
1. **What you have.** The decision brief in this conversation, if there is one, and what the person just said.
2. **Ask once, only for what is missing.** The record needs: the option chosen, why in the person's words, and who they talked with or who decided. If any of these is missing, ask for all the missing ones in one short question. Do not ask for anything else.
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

## Still open
- <what the brief left open that this decision does not settle> [link]

## Sources
- <the documents and threads the decision leans on> [link]
```

Under Why and Talked with, write only what the person said. Under Rejected, Still open and Sources, write only what the brief or the sources hold, with their links.
4. **Confirm.** Show the draft and ask whether to keep it. Change what they correct.
5. **Write** it to `decisions/<YYYY-MM-DD>-<short-slug>.md` at the root of the current git repository (or of the current folder outside one), or to the folder the person named. If a record of the same decision is there, update it and note the change under a `## Changes` heading with the date, instead of writing a second file.
6. Say where it was written, and that committing it shares it with the team and lets the next decision brief find it.
