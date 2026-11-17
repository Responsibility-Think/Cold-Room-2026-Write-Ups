# Operation Cymbal: Cold Room (2026) — Write-Ups

Write-ups from **Operation Cymbal: Cold Room**, a blue-team investigation event hosted by the Google Cloud Security Community on the Hack The Box CTF platform (29 October – 1 November 2026). Three incidents in one frozen environment, investigated in Google Security Operations (SIEM search and SOAR) across identity, endpoint, cloud, mail and build-system telemetry.

Each note documents the full method, not just the solve path — every query, the raw-log fields read, the decoys ruled out, and the wrong turns with the reason each one was taken.

Three rooms, one per category. **Result: 357th of 1,676 teams · 2,075 points · 18 of 18 flags** — played solo as `Project_Hydra_Strike`.

---

## Index

### Rooms

| # | Room | Category | Difficulty | Points | Flags | Focus | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 01 | [Deceptive Click](HTB-COLDROOM2026-Deceptive-Click-FakeUpdates-DriveBy-Kerberoast-WinRM-Data-Staging.md) | Investigation | very easy | 700 | 6 / 6 | Drive-by fake browser update, Kerberoasting, WinRM lateral movement, data staging | Solved |
| 02 | [Rogue Synthesis](HTB-COLDROOM2026-Rogue-Synthesis-Malicious-VSCode-Extension-Cloud-Token-Theft-CICD-Build-Hook.md) | AI Misuse | medium | 850 | 6 / 6 | Look-alike VS Code extension calling an LLM API, cloud token theft, CI/CD build hook | Solved |
| 03 | [OAuth Heist](HTB-COLDROOM2026-OAuth-Heist-Identity-Compromise-OAuth-Persistence-Service-Account-Reuse.md) | Threat Hunting | easy | 850 | 6 / 6 | Identity compromise, OAuth app persistence, service-account reuse, mailbox purge | Solved |

### Event method

| Note | Content |
| --- | --- |
| [Operation Cymbal: Cold Room — Event MOC](00_MOC-HTB-COLDROOM2026-Operation-Cymbal-Cold-Room-Event.md) | Room index, the shared end-game across the three intrusions, console and time-basis pitfalls, a Diamond Model view, and an ATT&CK roll-up |

---

## Notes

- **Points** in the table are the values recorded at solve time; they total 2,400. HTB scores dynamically, and the final team total was 2,075.
- Every room is question-graded; no `HTB{}` string exists in any of them. Answers are published because the event has closed.
- The notes are published as written in an Obsidian vault. `[[wikilinks]]`, callouts and Mermaid diagrams may render differently on GitHub; every link points to another note in this repo.
- MITRE ATT&CK mappings appear in every note's frontmatter and are re-checked against ATT&CK v20. Weak or unverified mappings are flagged as such in the note; treat them as working hypotheses rather than citations.

## Use

Licensed CC BY 4.0 — reuse freely with attribution. Scenario names, prose and artefacts remain the property of their owners.
