---
name: decision-record
description: Keep a decision the person has just made as a record their team can read later, a person who was not there and a person on the business side included: what happened, what there was to choose and what each option cost, what was chosen and why, what changes, what is still open, and the sources. Use when the person says what they decided (for example "we're going with SQS", "decided: Kafka, after talking with the platform lead", "record this decision"), or answers with a choice a card the assistant put to them, in any language, above all after a decision brief.
---

# Decision record

What decides a decision is often never written down: a talk with someone, a table someone made. Your job is to keep it, with almost no work from the person. They say one line; you draft the rest from what this conversation already has, they confirm, and you write one file.

## Rules
- The reason is the person's. Never invent a reason or a person. Take the reason only from what the person said, and the options, trade-offs and links only from the brief or the sources in this conversation.
- Write only inside the decisions folder. Never write, post or comment anywhere else. Send the record nowhere but to the person's Beaket team, encrypted by the plugin, and only after they confirm or answered a card with a choice.
- Write the record, its headings included, and every reply in the language the person wrote in. Korean is 해요체 (~해요, ~했어요) everywhere a person reads, the record above AI가 지킬 것 and every reply included; never 합니다체, 한다체 or -십시오. An option's name stays as written; a record already written keeps its register.
- The plugin's script is `<skill>/scripts/beaket.mjs`, where `<skill>` is this skill's folder. Run the script on its own, never chained with other commands by `;`, `&&` or `|` nor run from another folder with `cd`, so that a permission that allows the script covers it.

## Steps
1. **What you have.** The decision brief in this conversation, if there is one, and what the person just said. With no brief here, find the documents, issues and threads the person's words refer to (the options, numbers and people they named) in the sources and the decision records, so that The choice, Constraints, Still open and Sources can be linked. Search with the subject being decided (for example ingress, order events), not only the options' names: a constraint (a deadline, a freeze, an audit, a security or legal rule) is often written without any option's name. Open the decision's issue and every issue it links: an agreement made in a linked issue often binds how the decision is carried out.
   **From a card.** When the person answered with a choice a card this session put to them (the SessionStart hook says how: one choice, what happened, each option with what it gets and what it costs, a recommendation, a last line saying the answer is kept), the card and the answer are the source, and nothing else: the record's title says what was decided, from the card's question and the option they chose ("~하기로 했어요" in Korean, never "~할지 정한다" nor "~하기로 했습니다"), keeping every limit the decision has (우선, 당분간, 방법은 아직 없음), and the card's title, its question, goes under The choice as that section's one-line question; its What happened, The choice (every option with its gain and cost) and Still open go in word for word, the option they chose is Chose (its name without the recommendation mark the question puts on it), and their words when they chose it, the notes they added to the option included, are Why. An answer that selected no option, notes only, is not a choice: keep nothing. When they gave no reason ("the first", "as you suggest", "let's do it"), Why quotes their words, says in a statement that they gave no reason (in Korean, "<이름>은(는) 이 선택지를 고르면서 이유는 말하지 않았어요."), and then gives the card's recommendation on a line of its own, chosen or not, as `The card's recommendation (Claude): <the option it recommended>. <its reason>` (`Claude의 추천:`, `カードの推奨(Claude):`), word for word, so that the page shows it apart as Claude's. Leave Talked with out. Add nothing that was not on the card or in their answer; do not ask anything (step 2) and do not show the draft (step 4). A card the what-to-decide skill put answers an item a record left open: end the record with the section it names, `## Answers` (답한 것, 答えたこと) and its one line `- <record id>: <item>`, so that the page and `next` offer that item no more. If they picked the question's last option, handing the question to the team, there is no decision and nothing is kept here: the hook says to run `hand` with the same card, and the question becomes a record left to decide (`decisions/2026-11-08-agent-question-handed-to-team.md` in beaket/beaket); a record that answers it later carries that record's id under Answers as above.
2. **Ask once, only for what is missing.** The record needs: the option chosen, why in the person's words, and who they talked with. The decider is the person unless they name someone else; do not ask for it. If the choice, the reason or the people are missing, ask for all the missing ones in one short question, and never ask again for what they already said. Do not ask for anything else.
3. **Draft**, leaving out a section with nothing in it:

```
# <the decision, one line, in words a teammate who was not there understands>

- Date: <today>
- Decided by: <who>
- Status: decided
- Review by: <a day, only when the person named one>

## What happened
<the situation, in two to four plain sentences, for a reader who was not there>

## The choice
<the question, in one line>
- <option, named by what it does>: + <what it gets> − <what it costs> [link]

## Chose
<the option chosen, one or two lines>

## Why
<the person's reason, in their words>

## Talked with
- <who>: <what they said that mattered, in the person's words>

## What changes
<what will be different for the team once this is done, in one or two plain lines>

## Still open
- <what the brief or the card left open that this decision does not settle> [link]

## Details
<one line: what follows is for agents, who keep to it>

## Constraints
- <what binds carrying out this decision, set or agreed elsewhere: a deadline, a freeze, a rule from a linked issue; never the details of another decision> [link]

## Premises
- <a fact this decision rests on, written as a claim an action could prove false: "the service token X does not exist", "the README's first paragraph follows ADR-027"; never an action to take, an adjective or a hope>

## Revisit when
- <what the person said would reopen this>

## Sources
- <the documents and threads the decision leans on> [link]
```

Everything above Details is for a reader who was not there, a person on the business side included: no file names, spec claim IDs, table, function or tool names, and each option named by what it does, never "option 2". In Korean the headings are 상황, 고를 것, 정한 것, 왜, 함께 이야기한 사람, 앞으로 달라지는 것, 아직 안 정한 것, AI가 지킬 것, 지켜야 할 조건, 이 결정이 맞으려면, 다시 볼 때, 출처, Rests on, which only step 6 writes, is 바탕이 된 결정, and Answers is 답한 것 (a record written with the older headings keeps them: 무슨 일인가, 바뀌는 것, 세부, 제약, 전제, 기대는 결정); in Japanese 何が起きたか, 選ぶもの, 決めたこと, 理由, 話した人, 変わること, まだ決めていないこと, 詳細, 制約, 前提, 前提とする決定, 見直すとき, ソース.

Under Premises, turn the Decision and the Why into claims about the world that a later action could contradict (what exists, what a document says, who uses what); an agent at the point of use reads these to tell a contradiction from a change of subject. Write no Rests on and no Related section: which decisions this one rests on is found in step 6 by AIs that did not see this conversation, and a Related section is no longer written (beaket/beaket#3205). The decision this one replaces goes on a `- Supersedes:` line under the head. Under Why and Talked with, write only what the person said; a fact from the sources that also argues against an option goes under The choice, as that option's cost, with its link, never under Why as their reason. Under The choice, Constraints, Still open and Sources, write only what the brief, the card or the sources hold, with their links. A document that lives only on this machine is named by its title ("the monetization priorities memo, a local file"), never by its path, and no secret, token or password goes anywhere in a record: `push` refuses a record that holds a path on this machine or a secret (beaket/beaket#3197). A line taken only from AI meeting notes (Gemini and the like), a vendor or one person's remark is marked as such (for example "(Gemini notes, not in the transcript)"); check AI notes against the transcript first, and leave out what the transcript contradicts. Still open holds questions about the decision itself, never a constraint already set (that goes under Constraints) nor gaps of your tools (an issue that would not open, a search that failed). A number or fact the person gave stays theirs under Why; link a source next to it only when that source holds the same number, and never one that does not. Write every number with its unit, and every person by the full name the sources give them, with their role the first time.
4. **Confirm**, except for a record from a card: answering the card was the consent, so first say in one line what changes, starting "그럼 앞으로 …" in Korean ("From now on …" in English), and ask nothing, then write it, find what it rests on and share it (steps 5 to 7) without showing it; if they correct that line, change the record and keep their correction under Why as their words. Check whether the person is in a Beaket team: `node <skill>/scripts/beaket.mjs status` (`<skill>` is this skill's folder, the one that holds this SKILL.md), run alone, prints "This folder's team" when the folder they work in has one and otherwise why not (no `.beaket/team`, a file not trusted, a team this machine is not in, or no team); only a folder with a team shares. Show the draft and ask one question only: whether to keep it, and, if they are in a team, to share it with the team. Everything else you need them to see goes in short statements around the draft, not in further questions: the lines marked as AI notes or one person's remark, for them to check; if they said nothing of when or why it would be looked at again, that they can add what would reopen it; if they did (for example "we look at it again in 2027"), that is Revisit when. Never put a placeholder such as "(to confirm)" in a draft: leave the section out. Change what they correct and nothing else: the file you write is the draft you showed, word for word, with only their corrections applied; keep the tone, the sections and every other word, role and number as they were. Remove or reword a line they did not correct, a Still open item above all, only when they say so; when something they said seems to settle it, keep it and say in the same answer that it stays unless they say to remove it.
   If the person wants something kept from the team (a staffing call, something personal, "only I should know"), it is private: write no part of it (the person, the change or the reason) into the repository, into an existing record or into the team's records, where a commit or a push would share it. Write nothing until you ask, in one line, whether to keep it at all (the default is no); if they do, write it to the private folder that `node <skill>/scripts/beaket.mjs paths` names, with `<!-- beaket-private -->` as its first line, and say where it is.
5. **Write** it to `decisions/<YYYY-MM-DD>-<short-slug>.md` at the root of the current git repository (or of the current folder outside one), or to the folder the person named. If a record of the same decision is there, update it and note the change under a `## Changes` heading as `- <YYYY-MM-DD> <who changed it>: <what changed>`, instead of writing a second file.
6. **Find what it rests on, with AIs that did not see this conversation**, once the file is written and before it is shared: you saw everything said here, so a decision talked about nearby would look like one it rests on. Run `node <skill>/scripts/beaket.mjs links <file>`, alone. It asks an AI that sees only the record and the list of the folder's decisions which it may rest on, asks another three times of each whether reversing that decision would make this one be decided again, writes under Rests on only those all three said yes to, and drops the rest, a split included: the person is not asked, since even the person who decided could not answer these (beaket/beaket#3205). Do not add, remove or reword a line it wrote, and say nothing of it to the person. When `links` cannot run `claude`, leave Rests on out and say so in one line. `push` refuses a record dated from 2026-11-10 on with a Rests on line `links` did not write, or a Related section.
7. If they are in a team and agreed to share or answered a card, or the record was already shared (its first line is `<!-- beaket-record: ... -->`) and they confirmed the change, run `node <skill>/scripts/beaket.mjs push <file>`. It encrypts the record on this machine; Beaket keeps it but cannot read it, and every member's next brief and session reads it. Beside the ciphertext, `push` sends the record's passport: its Date, Review by and state in the clear, and its title, Decided by and the links under Sources, Rests on and Supersedes sealed with the team key, as the record is. Say so in the same line when it is the first push of a record.
8. Say where it was written and whether it was shared. If they are in no team, say in one line that they can ask to make a Beaket team to share records with teammates, end-to-end encrypted.
9. **When a premise changed.** When a session finds that a request goes against a shared record (the SessionStart hook says how to stop and what to ask) and the person answers that the premise changed, update that record, not a new file: the change, the date and who answered under `## Changes`, the premise rewritten or struck under Premises, and `- Status: changed` when the decision no longer stands as written. Show the change, and after they confirm, `push` the file and run `node <skill>/scripts/beaket.mjs answer <file> changed`, which tells Beaket who answered and when, with none of the words. When they answer that the premise did not change, run `answer <file> unchanged` and change nothing in the record. Offer this once, in one line, and do not ask again if they decline.
