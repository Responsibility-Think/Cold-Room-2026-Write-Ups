---
type: moc
title: "HTB Cold Room 2026 — Operation Cymbal: Event MOC and Cross-Room Method"
platform: Hack The Box
event: "Operation Cymbal: Cold Room"
status: complete
domain: "DFIR · Threat Hunting · SIEM investigation"
scope: "Three Google SecOps investigation rooms in tenant ctf-us-03 — Deceptive Click, Rogue Synthesis, OAuth Heist"
cert: "none — CTF event"
course: "none — CTF event"
last_audited: 2026-11-15T18:50:46.550Z
source: "Hack The Box CTF event 3631, 29 Oct – 01 Nov 2026"
tags:
  - MOC
  - HTB
  - Security
  - DFIR
  - Threat_Hunting
  - Incident_Response
  - Log_Analysis
  - SIEM
  - kill-chain
  - lateral-movement
  - exfiltration
related:
  - "[[HTB-COLDROOM2026-Deceptive-Click-FakeUpdates-DriveBy-Kerberoast-WinRM-Data-Staging]]"
  - "[[HTB-COLDROOM2026-Rogue-Synthesis-Malicious-VSCode-Extension-Cloud-Token-Theft-CICD-Build-Hook]]"
  - "[[HTB-COLDROOM2026-OAuth-Heist-Identity-Compromise-OAuth-Persistence-Service-Account-Reuse]]"
aliases:
  - Cold Room 2026 MOC
  - Operation Cymbal
  - Operation Cymbal Cold Room
  - Cymbal Cold Room
created: 2026-10-30T10:33:37.301Z
---

# Operation Cymbal: Cold Room — Event MOC and Cross-Room Method

> [!warning] Exercise environment
> Cymbal Investments, its staff, hosts and data are fictional. Everything below reconstructs a Hack The Box training scenario played in a shared Google SecOps tenant (`ctf-us-03`).

> [!info] Scope of this note
> Indexes the three investigation rooms solved in this event. Every cross-room claim below is drawn from those three notes. Where a pattern rests on fewer than three rooms, it says so. Confidence tags follow the writeups: **[Certain]** read from a raw log field; **[Inference]** drawn from two or more records; **[Guessing]** a lead, not a finding.

---

## 1. Room index

| # | Room | Category | Difficulty · points | Flags | Entry vector | End state | Note |
|---|---|---|---|---|---|---|---|
| 01 | Deceptive Click | investigation | very easy · 700 | 6/6 | Drive-by fake browser update (FAKEUPDATES pattern) | Finance audit files staged on the file server | [[HTB-COLDROOM2026-Deceptive-Click-FakeUpdates-DriveBy-Kerberoast-WinRM-Data-Staging]] |
| 02 | Rogue Synthesis | AI Misuse | medium · 850 | 6/6 | Look-alike VS Code extension calling an LLM API | Production build script on the CI runner overwritten | [[HTB-COLDROOM2026-Rogue-Synthesis-Malicious-VSCode-Extension-Cloud-Token-Theft-CICD-Build-Hook]] |
| 03 | OAuth Heist | Threat Hunting | easy · 850 | 6/6 | Personalised credential-phishing link | Customer database backup exfiltrated; ransom note left | [[HTB-COLDROOM2026-OAuth-Heist-Identity-Compromise-OAuth-Persistence-Service-Account-Reuse]] |

**18 of 18 flags accepted — all three rooms "Scenario Pwned" on 2026-10-30.** 2,400 points across the three rooms at solve time. **Event result: 357th of 1,676 teams · 2,075 points · 18 of 18 flags** — read off the HTB team page, not recalled; HTB scores dynamically, so the final total sits below the solve-time values. Every room is question-graded; no `HTB{}` string exists in any of them.


---

## 2. The environment — one tenant, three segments

All three intrusions sit in the same fictional network on the same day, **2026-10-15 (UTC)**. [Certain]

| Room | Victim workstation | Pivot target(s) | Accounts misused | Planted noise |
|---|---|---|---|---|
| Deceptive Click | `CYM-DEN-W10-042` · 10.240.32.115 · `marcus.vance` | `CYM-DC-01` 10.240.10.2 (Kerberoast, SMB probe) · `CYM-FS-01` 10.240.10.50 (staging) | `marcus.vance`, `svc_backup` (SID …-1088) | `sarah.jenkins` — `nightly_backup.ps1` on FS-01 |
| Rogue Synthesis | `CYM-DEV-WS-019` · 10.240.12.80 · `alex.chen` | `CYM-CI-RUNNER-01` 10.240.12.85 (build-script overwrite) | `alex.chen`, `svc_cicd_deploy` | `sarah.jenkins` — backup copy of the same build script, plus `gcloud auth list` |
| OAuth Heist | `CYM-DATA-WS-007` · 10.240.12.65 · `elena.rostova` | `CYM-DB-01` 10.240.12.100 (backup, compress, exfil) | `elena.rostova`, `svc_dbadmin` (SID …-1089) | `sarah.jenkins` — WinRM session and `sql_health_check.ps1` on DB-01 |

`sarah.jenkins` works from `CYM-ADMIN-WS-002` (10.240.12.45) in the two rooms where her source host is logged.

**Log sources across the event:**

* Zscaler NSS web proxy
* Windows Sysmon (EID 1 / 3 / 8 / 11, with `RuleName` pre-labelled by the scenario author)
* Windows Security (4624, 4769)
* Okta
* Google Workspace audit (login, OAuth grant, Gmail, Drive)

Not every source appears in every room.

---

## 3. Narrative spine

Three different entry points, one end-game. Each paragraph cites only what its room's raw logs show.

**Deceptive Click (endpoint-first).** A Denver employee reached a compromised blog (`marketingtrends-insider.com`) and downloaded a fake Chrome update archive. Script execution led to a hidden download of a second-stage binary, which hollowed a SYSTEM `svchost.exe` (PID 624). The operator ran domain discovery and requested an RC4 Kerberos service ticket for `MSSQLSvc/CYM-DB-01.cymbal.corp:1433`. Thirteen minutes later, the service account behind that SPN, `svc_backup`, logged on to the file server over NTLM and WinRM, and finance Q3 audit files were archived into `C:\Windows\Temp\Financial_Audit_2026.zip`. **No exfiltration observed.** [Certain]

**Rogue Synthesis (developer supply chain).** A developer installed `SyntaxOptimizer-2.1.4.vsix` from a look-alike marketplace host. The extension's daemon called the Gemini API (`gemini-1.5-flash-latest`, the model the GTIG report names for PROMPTFLUX), then compiled a payload locally with the developer's own toolchain. That payload hollowed `svchost.exe` (PID 624) and read `.gcloud\credentials.db`. Harvested data went out to a fake telemetry endpoint (`dev-metrics-cdn.com/api/v2/telemetry`). The deploy service account `svc_cicd_deploy` then reached the CI runner over WinRM and overwrote `build_production.ps1`. **No pipeline run of the modified script observed.** [Certain]

**OAuth Heist (identity-first).** A data analyst opened a phishing link personalised with her own username. The adversary took over her Okta and Workspace identity from two separate external addresses, enrolled their own MFA factor and authorised a mailbox app, "ToogleBox Recall". They used that app to purge the two security alerts sent to her. A Drive search surfaced a database-architecture PDF holding service-account credentials. `svc_dbadmin` was then used from her workstation to reach the SQL server over WinRM, where the customer database was backed up, compressed and uploaded (≈485 MB) to `142.11.200.188:8888`, and a ransom note was left. **No endpoint persistence; cloud footholds never shown removed.** [Certain]

---

## 4. Cross-room patterns — candidates for "the Tell"

The event brief promises a detail that could connect one operator to all three incidents. These are the candidates. None is proven to be *the* Tell. [Guessing on intent; confidence on each observation as tagged.]

| Pattern | DC | RS | OH | Confidence |
|---|---|---|---|---|
| Same day, 2026-10-15 | ✓ | ✓ | ✓ | [Certain] |
| Privileged **service account** reused to reach a high-value server | `svc_backup` → FS-01 | `svc_cicd_deploy` → CI-RUNNER-01 | `svc_dbadmin` → DB-01 | [Certain] |
| Remote shell is **WinRM** (`wsmprovhost.exe -Embedding` parent on the target) | ✓ | ✓ | ✓ | [Certain] |
| **Planted maintenance admin** `sarah.jenkins` on the same target host, same window | ✓ | ✓ | ✓ | [Certain] |
| Hollowing target is **`svchost.exe` PID 624** (`-k netsvcs -p`, SYSTEM) | ✓ | ✓ | — (no hollowing) | [Certain] |
| Exfil or beacon path shaped **`/api/v*/telemetry`** | `cdn-metrics-analytics.net/api/v1/telemetry` | `dev-metrics-cdn.com/api/v2/telemetry` | — (`/upload/` instead) | [Certain] on the paths |
| **Sequential service-account SIDs** | …-1088 `svc_backup` | not recorded | …-1089 `svc_dbadmin` | [Certain] on the two values |
| Same client **source port 52180** on the pivot's 4624 | ✓ (FS-01) | — (52140) | ✓ (DB-01) | [Certain] |
| External hosts in Cloudflare-range address space | blog, CDN, stage-1 C2 | exfil host | adversary Okta sign-in IP (AS13335, per Okta); phishing host [Unverified] | [Inference] from ranges, except the Okta tag [Certain] |

**[Inference]** The strongest operator-level join is behavioural, not infrastructural: all three converge on *service-account reuse over WinRM to a single data server*. The weakest candidates (PID 624, port 52180, sequential SIDs) are as likely to be scenario-authoring shortcuts as operator fingerprints. The writeups record PID reuse inside Deceptive Click as an authoring artefact for exactly that reason.

### 4.1 Activity-group test — the three diamonds compared

Activity groups belong in the event MOC, not in a writeup. Each room's summary diamond is in its writeup: Deceptive Click §3.9, OAuth Heist §3.2, Rogue Synthesis §3.2. Built 15 Nov 2026 from those notes; no new log queries. Method: the Diamond Model of Intrusion Analysis.

**Feature comparison — what joins the rooms**

| Feature | Vertex | DC | RS | OH | What kind of overlap |
|---|---|---|---|---|---|
| Same day, overlapping windows | Meta | ✓ | ✓ | ✓ | Scenario design |
| Service account reused over WinRM to one data server | Capability | ✓ | ✓ | ✓ | Behavioural — the only feature in all three that an operator, not the environment, chooses |
| Hollowing target `svchost.exe` PID 624 | Capability | ✓ | ✓ | — | A value the scenario author sets. PIDs are not stable across real hosts |
| `/api/v*/telemetry` beacon or exfil path | Infrastructure | ✓ | ✓ | — | Infrastructure habit |
| Client source port 52180 on the pivot logon | Capability | ✓ | — (52140) | ✓ | Ephemeral port. Not attribution evidence in a live network |
| Sequential service-account SIDs (…-1088, …-1089) | Victim | ✓ | not recorded | ✓ | Victim-side object-creation order, not an adversary trait |
| Look-alike domain imitating a trusted brand | Infrastructure | fake update CDN | fake marketplace | fake SSO | Common tradecraft |
| Cloudflare address space | Infrastructure | blog, CDN, stage-1 C2 (172.67 / 104.21) [Likely, from ranges] | exfil host 172.67.210.44 [Likely, from range] | adversary Okta IP, AS13335 per Okta [Certain] | Commodity hosting |
| Documentation-range address `198.51.100.84` (RFC 5737) | Infrastructure | ✓ | — | — | Proof of scenario authoring [Certain on the range] |
| Planted admin `sarah.jenkins` near the target | Victim | ✓ | ✓ | ✓ (incl. 18:45 Okta enrolment) | Scenario design |
| Victim department and entry vector | Victim / Capability | Marketing · drive-by | Cloud · supply chain | Data · identity | Three different playbooks |

**Activity-group test**

| Hypothesis | Supports | Against |
|---|---|---|
| **H1 — one operator across all three** | Service-account-over-WinRM convergence in all three; same day | Three unrelated entry playbooks; three disjoint infrastructure sets; the shared values are ones an author, not an operator, controls |
| **H2 — one scenario author, no single operator implied** | Overlaps cluster in author-set values (PID 624, port 52180, sequential SIDs, the planted admin, the date); one address sits in a documentation range | Does not explain why the event brief promises a "Tell" |
| **H3 — independent actors** | Disjoint infrastructure and victims | Too many shared author-level values for pure coincidence |

**Assessment.** [Inference] H2 explains the evidence best. The overlaps that would mean something in a real investigation are behavioural and common: service-account reuse over WinRM is standard post-exploitation, not a signature. The overlaps that look like signatures (PID 624, port 52180, sequential SIDs) are values an exercise designer controls, and none of them reaches all three rooms. Within the exercise's own fiction, the strongest two-room links are **Deceptive Click ↔ Rogue Synthesis** (PID 624 plus the telemetry path) and **Deceptive Click ↔ OAuth Heist** (port 52180 plus sequential SIDs). No feature joins all three except the behaviour and the scenario furniture.

---

## 5. Cross-room method — the transferable rules

### 5.1 The raw log is the answer; summaries are orientation

Deceptive Click flag 3 is the proof. The SOAR case's Gemini summary reported the hollowed svchost as PID 6124; the Sysmon EID 8 record shows 6124 is the **source** and **624** the target. In all three rooms the routine was the same: open the row → **Raw Log** tab → read the vendor-native field → accept. 18 of 18 answers were taken that way. The raw record also holds fields UDM never maps: in OAuth Heist the app's `client_id` exists only in the raw Gmail record, so a UDM search for it finds the grant and misses both purges. Search on a mapped field (there, the adversary IP), then read the raw records. [Certain]

### 5.2 The grid lies about two things

* **Time:** the results grid renders **+1 h** against raw UTC for every row type checked, detection rows included; the time-range picker uses the browser's local time. Gmail `EMAIL_TRANSACTION` rows only *look* like +3 h: they carry their **ingestion** time as the event time (OAuth Heist purge: action 19:05:19Z, ingested 21:11:13Z, shown 22:11:13). [Certain] the offsets, re-read 31 Oct. [Unverified] the cause.
* **Host:** on Windows 4624 the grid's `Hostname` column shows `WorkstationName`, the **source**. In both Deceptive Click and OAuth Heist, a service-account logon to a server looked like a workstation logon until the raw `Hostname` was read.

### 5.3 Pivot on the client IP, not the hostname

Proxy events and DC-side Kerberos events in this tenant carry the client IP, not the client hostname. `principal.hostname = /CYM-DC-01/` returns nothing for a 4769 recorded on that DC. **Get the workstation IP from the case or the first endpoint search, then search the IP.**

### 5.4 Eliminate the planted admin by four fields

`sarah.jenkins` touches the target server in every room, close in time to the adversary. Each time, four fields separate her from the intrusion:

* **Source host:** `CYM-ADMIN-WS-002`, not the victim workstation
* **Logon session ID:** different from the adversary's
* **Parent process:** interactive `explorer.exe`, not `wsmprovhost.exe`
* **Script path:** `C:\AdminScripts\…`

In Rogue Synthesis she backed up **the same file** the adversary later overwrote — the sharpest decoy in the event.

In OAuth Heist she also enrolled an Okta MFA factor at **18:45:09 UTC**, three minutes after the victim's password was stolen. The same kind of separation holds: her own admin workstation (`CYM-ADMIN-WS-002`, internal 10.240.12.45), device "MacBookPro18,1", event type `device.mfa.register` rather than the adversary's `user.mfa.factor.activate`, Okta severity INFO, and no match to the rogue factor's fingerprint. [Certain] on the raw record. [Inference] legitimate. Found by the 31 Oct Okta namespace hunt (OAuth Heist writeup §5).

### 5.5 Read the threat-report attachment for shape, not strings

Each room ships a GTI or GTIG PDF:

* **Deceptive Click** — FAKEUPDATES profile. The tenant reused one C2 URL and the `d27e15eb` filename stem; none of the report's other IOCs appeared.
* **Rogue Synthesis** — AI Threat Tracker. The tenant reused the API host, the model string and the "Thinking Robot" artefact name; the malware form (a VS Code extension, not VBScript) did not match.

**Search on infrastructure and behaviour, not on the report's IOC list.**

### 5.6 Scope wide searches away from the tenant's other datasets

The tenant is shared with unrelated demo data, which buries Cymbal rows in unscoped searches. Scope by the Cymbal namespace, the victim, or the victim's IP before reading a result set. Noise datasets seen:

* `MUGATU` / `hanselmcdonald` AI-API traffic
* `charlie.brown` daily Workspace alerts
* `mikeross` / `timaddler` service-account emails
* `linminer-*` registry and service events

### 5.7 The Lockheed Kill Chain compresses these intrusions

Two of the three rooms used no implant beyond a single hollowed process, and OAuth Heist used none at all. In every room most activity sits in *Actions on Objectives*. **For identity-led or living-off-the-land intrusions, break that phase into its individual steps and add a Unified Kill Chain (*In → Through → Out*) view.**

### 5.8 Absence findings are bounded by what was logged

Three gaps recur:

* **No source-side record:** OAuth Heist's lateral move has none, because the victim workstation logged no outbound connection.
* **Files known only from command lines:** data files appear in command lines with no file-creation record, in OAuth Heist and Deceptive Click.
* **No file hashes:** neither room's Sysmon records carry any.

"Nothing found" holds only for the event types that exist.

---

## 6. Cross-room defensive takeaways

| Control | Would have hurt | Rationale |
|---|---|---|
| **Service-account governance** — deny network logon except from designated hosts; gMSA; no RC4 | All three | Every room's pivot was a service account used from a user workstation [Inference] |
| **Alert on WinRM sessions from user workstations to servers** | All three | `wsmprovhost.exe` under a service account on a data server was the common remote-shell signature |
| **Secrets out of documents and local credential stores** | RS, OH | `.gcloud\credentials.db` and a Drive PDF each handed over a privileged credential |
| **Server egress default-deny** | DC (beacons), RS, OH | Every exfil or beacon went over allowed HTTP(S) with `threatname=None` |
| **Look-alike domain watch** | All three | `marketingtrends-insider.com` → fake CDN; `marketplace.visualstudio.com.cdn-cache.net`; `sso-cymbal-portal.com` |
| **Phishing-resistant MFA, admin-gated MFA enrolment, OAuth allow-list** | OH | Identity takeover and the mailbox app both matched detections, but those were generated only after the data had left (21:11 and 23:05 UTC, against the 20:58 exfiltration) |

---

## 7. ATT&CK coverage by room

IDs from each writeup's `mitre:` catalog, mapped to **ATT&CK v20**. No ID in this table changed between v19 and v20; v19 renamed Defense Evasion (TA0005) to **Stealth**. Mapping honest-scope notes live in each writeup's ATT&CK section.

| Tactic area | Deceptive Click | Rogue Synthesis | OAuth Heist |
|---|---|---|---|
| Initial access | T1189 | T1195.002 | T1566.002 · T1598.003 *(recon)* |
| Execution | T1204.002 · T1059.007 · T1059.001 | T1204.002 · T1059.007 | — |
| Persistence / privilege | T1055.012 | T1055.012 | T1098.005 · T1556.006 · T1671 |
| Stealth *(was Defense Evasion)* | T1036.008 · T1055.012 | T1055.012 | T1070.008 |
| Credential access | T1558.003 | T1552.001 | T1552.001 |
| Discovery | T1087.002 · T1018 · T1083 | — | T1213 *(collection)* |
| Lateral movement | T1021.002 · T1021.006 · T1078.002 | T1021.006 · T1078.002 | T1021.006 · T1078.002 · T1078.004 · T1570 |
| Collection / staging | T1560.001 · T1074.001 | — | T1560.001 |
| C2 / exfiltration | T1105 · T1071.001 | T1041 · T1071.001 | T1048.003 |
| Impact | — | — | T1657 |

**Common to all three:** T1021.006 (WinRM) and T1078.002 (a domain service account). **Shared by two:** T1055.012, T1204.002, T1059.007, T1560.001, T1552.001, T1071.001.

---

## 8. Open threads

1. ~~**Deceptive Click flag 6 acceptance**~~ — **closed 2026-10-30**: accepted; room pwned at 04:53 platform-local.
2. **OAuth Heist delivery channel** — the phishing link was personalised (`?user=` equal to the victim's username) but no lure email exists in corporate Gmail. Phone, text or chat is unproven.
3. **OAuth Heist workstation-side gap** — how the adversary acted *from* `CYM-DATA-WS-007` to start the `svc_dbadmin` logon is not logged.
4. ~~**Four OAuth Heist times are grid-derived**~~ — **closed 2026-10-31**: all four re-read from raw records (18:48:09, 18:49:29, 18:55:24, 19:01:19 UTC).
5. ~~**Gmail `action_type 71`**~~ — **closed 2026-11-15**: Google's Gmail log schema defines code 71 as a post-delivery user action (opening, clicking a link, downloading an attachment), not deletion. The "purge" is the scenario's framing (OAuth Heist writeup §13, which cites the source).
6. **`linminer-01` / `linminer-02`** — service and registry events seen in a broad persistence search and not examined. Out of scope unless they turn out to be in the Cymbal namespace.
7. **Rogue Synthesis credential source** — how `svc_cicd_deploy` was obtained from the harvested data is not logged.
8. **The Tell** — §4 lists candidates and §4.1 tests them as an activity group. No single technical feature joins all three rooms; the best two-room links are Deceptive Click ↔ Rogue Synthesis (PID 624, telemetry path) and Deceptive Click ↔ OAuth Heist (port 52180, sequential SIDs). Still open.
9. ~~**Stale line in the OAuth Heist writeup §13**~~ — **closed 2026-11-15**: the writeup now records her 18:45, 19:43 and 21:11 activity. Original note: says `sarah.jenkins` "does not appear here". She does, on DB-01 at 19:43 and 21:11 (found after that note was written). Reported here, not fixed in place.
10. ~~**Publication not cleared**~~ — **cleared 17 Nov 2026**: neither the HTB event page nor the Google Cloud Security Community event page and two organiser threads set any rule on write-ups, and HTB's general CTF rules restrict sharing only during the competition.

---

## Cross-references

* [[HTB-COLDROOM2026-Deceptive-Click-FakeUpdates-DriveBy-Kerberoast-WinRM-Data-Staging]]
* [[HTB-COLDROOM2026-Rogue-Synthesis-Malicious-VSCode-Extension-Cloud-Token-Theft-CICD-Build-Hook]]
* [[HTB-COLDROOM2026-OAuth-Heist-Identity-Compromise-OAuth-Persistence-Service-Account-Reuse]]

---

## Change Log

- 2026-11-15 — `status` active → complete: the event closed 01 Nov 2026, all 18 questions solved, and the notes are now in polishing. Open threads in §8 stay as analytical leftovers, not unfinished writing. `last_audited` set to the 15 Nov final audit.
- 2026-11-15 — Final-audit fixes. New §4.1 activity-group test (the three room diamonds compared). §4 Cloudflare row: OAuth Heist cell confirmed through Okta's AS13335 tag. §8: thread 5 closed, thread 8 reframed, thread 10 (publication) added.
- 2026-11-15 — §7 Rogue Synthesis column synced with the writeup's corrected `mitre:`: T1003.008 and T1505.003 removed (scenario-author labels the evidence does not support).
- 2026-11-15 — §8 thread 9 closed after the OAuth Heist writeup refresh.
- 2026-11-15 — Audit refresh. §5.4 adds sarah.jenkins' 18:45 Okta enrolment in OAuth Heist. §6 OAuth row: detections were generated after the exfiltration, not alerts left unanswered. §7 remapped to ATT&CK v20 (Stealth row; OAuth Heist T1671, T1556.006, T1598.003, T1213, T1570, T1657 replace T1528, T1213.002, T1491); "common to all three" corrected to include T1078.002.
- 2026-11-04 — Cross-references: added the Diamond Model of Intrusion Analysis with a one-line suggested exercise (one diamond per room → activity group). No other change.
- 2026-10-31 — §5.1 adds the UDM field-mapping gap. §5.2 time rule corrected (Gmail rows show ingestion time, not a fixed +3 h). §8 thread 4 closed.
- 2026-10-30 — Deceptive Click flag 6 accepted: §1 row and summary now 18/18, §8 thread 1 closed.
- 2026-10-30 — Note created. Indexes the three Cold Room rooms:
  * §4 records the cross-room "Tell" candidates.
  * §5 records eight transferable method rules, each tied to the room that earned it.
  * §8 carries open threads from all three notes.

  `type: moc` with the frontmatter extension fields (`domain`, `scope`, `cert`, `course`, `last_audited`, `source`) populated; `cert`/`course` set to "none — CTF event". `status: active` while the event runs (closes 01 Nov 2026). `updated` omitted per §1 (plugin-owned).
