# CASE-ALT3-00004-1-BBEBE735 — Regular outbound connection intervals

Synthetic SOC training case. All indicators and response actions are simulated.

| Field | Value |
| --- | --- |
| Alert | ALT3-00004 |
| Case | CASE-ALT3-00004-1-BBEBE735 |
| Attempt | 1 |
| Dataset version | 3 |
| Sequence profile | network-7 |
| Status | Escalated |
| Severity | Critical |
| Verdict | True Positive |
| Disposition | Escalate to L2 |
| Analyst | SOC Analyst L1 |
| Detected | 2026-09-09T11:37:30.000Z |
| Submitted | 2026-11-12T21:43:53.485Z |
| User | r.patel |
| Endpoint | FIN-LT-001 |
| Domain | sync-0.test |
| Artifact SHA256 | c63c2a6fc849c0170674fc5b87574a458c6bd46737c233a3a74c044d46d35c72 |
| Hints used | 2 |
| SLA policy | from_case_creation |
| SLA hours | 1 |
| SLA due | 2026-11-12T22:23:16.532Z |

## Escalation summary

Escalating as a suspected True Positive. msiexec.exe on FIN-LT-001 silently installed an invoice-named MSI from the user’s Temp folder and then made 53 outbound TLS connections to the uncategorized domain sync-0.test at a steady 113-second interval, sending more data (124,574 bytes) than it received (40,264). This matches C2 beaconing with possible data transfer (MITRE T1218.007, T1071.001). [A cluster of failed logons against r.patel preceded the session, suggesting possible credential compromise.] The signed Windows binaries and standard port 443 do not clear the activity, because they only show a legitimate tool was abused. Containment and a decision on the MSI’s contents need L2 authority.

**Next step:** Isolate FIN-LT-001 from the network.
Collect and detonate/analyze Invoice_2926.msi (SHA256 c63c2a6f...d35c72) in a sandbox.
Block sync-0.test and 192.0.2.1 at the proxy/firewall and DNS.
Reset r.patel’s credentials and review the sign-in history and MFA [given the failed-logon cluster].
Hunt for the same MSI hash and sync-0.test connections across other endpoints.
Determine how the MSI reached the Temp folder (email attachment or download) and review r.patel’s recent mail.

## Observed activity

On 09 Sept 2026, r.patel’s session on FIN-LT-001 (root: explorer.exe, ALT3-00004-E010, 11:17:08 UTC) led to msiexec.exe /i "C:\Users\r.patel\AppData\Local\Temp\Invoice_2926.msi" /qn (ALT3-00004-E012, 11:31:34 UTC), a silent install of an invoice-named MSI from the Temp folder. The msiexec process then made repeated outbound TLS connections to sync-0.test (ALT3-00004-E014, 11:36:24 UTC): 53 connections at 113-second intervals, with 124,574 bytes sent and 40,264 received.

## Evidence reviewed

AALT3-00004-E010 (session root process, 4688, 11:17:08): explorer.exe (PID 1000, PPID 640), valid signature, no connections. This is the user’s normal session root and does not itself indicate compromise.
ALT3-00004-E012 (process start, 4688, 11:31:34): msiexec.exe (PID 1028, PPID 1012) with command line /i "C:\Users\r.patel\AppData\Local\Temp\Invoice_2926.msi" /qn, valid signature, Medium integrity, connection to 192.0.2.1:443 (sync-0.test).
ALT3-00004-E014 (outbound network, 11:36:24): msiexec.exe (PID 1028) to https://sync-0.test/session/0 over TLS 443, interval 113s, connection count 53, 124,574 bytes sent / 40,264 received, firewall action Allowed, status 200, proxy category Uncategorized.

## IOC findings

sync-0.test (192.0.2.1:443), proxy category Uncategorized, contacted 53 times by msiexec.exe. Artifact: Invoice_2926.msi in AppData\Local\Temp, SHA256 c63c2a6fc849c0170674fc5b87574a458c6bd46737c233a3a74c044d46d35c72. msiexec.exe image SHA256 15839c30e072a119e9dc442ca3b5186968812fa0a2ae824c9cabb0490127d47c.

## Endpoint findings

On FIN-LT-001, msiexec.exe (PID 1028, parent PID 1012) silently installed an MSI from the user’s Temp folder (ALT3-00004-E012). The binary is in System32 with a valid publisher signature at Medium integrity, which only shows the real Windows Installer was used, not that the package is safe. The invoice-style MSI name, the Temp location and /qn suppression are consistent with a malicious installer lure. The session root (E010, explorer.exe) is normal.

## Authentication findings

No credential-attack pattern is evident in the reviewed records.

## Network findings

ALT3-00004-E014: msiexec.exe (PID 1028) connected outbound to sync-0.test over TLS/443 (GET /session/0, status 200, Allowed) with a consistent 113-second interval across 53 connections, which indicates beaconing. Bytes sent (124,574) exceed bytes received (40,264), which could indicate data leaving the host, although the 200 response and standard port show nothing malformed. Msiexec is not expected to run repeated outbound sessions.

## Scope assessment

Activity confirmed on one endpoint (FIN-LT-001) and one user (r.patel). The chain runs from the session root explorer.exe (ALT3-00004-E010, 11:17:08 UTC) to the silent install msiexec.exe /i "...\Temp\Invoice_2926.msi" /qn (ALT3-00004-E012, 11:31:34 UTC) to 53 outbound connections at 113-second intervals to sync-0.test (ALT3-00004-E014, from 11:36:24 UTC). A cluster of [number] failed logons (4625) against r.patel was also found [from source IP, between times, followed or not followed by a 4624 success]. [Result of domain contains "sync-0": no other host or user contacted sync-0.test /. [Result of searching hash c63c2a6f...d35c72: the MSI was / was not seen on other endpoints.] No lateral movement or privilege escalation was observed (Medium integrity). Scope is assessed as one endpoint and one account with suspected compromise, pending L2 confirmation. Association between records does not establish compromise.

## Affected assets

Endpoint: FIN-LT-001 (finance laptop), which ran the installer and made the connections
User account: r.patel, whose session executed the activity and who was the target of [number] failed logons
Artifact: C:\Users\r.patel\AppData\Local\Temp\Invoice_2926.msi (SHA256 c63c2a6fc849c0170674fc5b87574a458c6bd46737c233a3a74c044d46d35c72)
External indicators: sync-0.test / 192.0.2.1 (TLS 443)
Possible data exposure: 124,574 bytes sent to sync-0.test in the sampled session (unconfirmed)
Not confirmed affected: other endpoints and accounts

## Actions taken

Reviewed the alert timeline and SIEM records (alert_id = "ALT3-00004"), bookmarked E010, E012 and E014, inspected r.patel’s identity baseline, decoded and assessed the process chain, and checked scope by domain and hash. Created case CASE-ALT3-00004-1-BBEBE735 and escalated to L2. Simulated response actions recorded: [what you actually selected, e.g. isolate FIN-LT-001, block sync-0.test / 192.0.2.1, reset r.patel’s credentials, collect Invoice_2926.msi for analysis].

## Escalation reason

Escalating as a suspected True Positive. msiexec.exe on FIN-LT-001 silently installed an invoice-named MSI from the user’s Temp folder and then made 53 outbound TLS connections to the uncategorized domain sync-0.test at a steady 113-second interval, sending more data (124,574 bytes) than it received (40,264). This matches C2 beaconing with possible data transfer (MITRE T1218.007, T1071.001). [A cluster of failed logons against r.patel preceded the session, suggesting possible credential compromise.] The signed Windows binaries and standard port 443 do not clear the activity, because they only show a legitimate tool was abused. Containment and a decision on the MSI’s contents need L2 authority.

## Recommended next step

Isolate FIN-LT-001 from the network.
Collect and detonate/analyze Invoice_2926.msi (SHA256 c63c2a6f...d35c72) in a sandbox.
Block sync-0.test and 192.0.2.1 at the proxy/firewall and DNS.
Reset r.patel’s credentials and review the sign-in history and MFA [given the failed-logon cluster].
Hunt for the same MSI hash and sync-0.test connections across other endpoints.
Determine how the MSI reached the Temp folder (email attachment or download) and review r.patel’s recent mail.

## Analyst notes

Supporting evidence: E012 shows msiexec.exe with /i Invoice_2926.msi /qn from AppData\Local\Temp (silent install, invoice-style name, finance user). E014 shows the same process (PID 1028) beaconing to sync-0.test every 113s across 53 connections, 124,574 bytes sent versus 40,264 received, proxy category Uncategorized, firewall Allowed. 
Contradicting or mitigating evidence: msiexec.exe is the signed Windows binary in System32 at Medium integrity. E010 is a normal explorer.exe session root with a valid signature and no connections. Traffic is standard TLS on port 443 with a 200 response, and the domain is uncategorized rather than flagged malicious. 
Assessment: behavior (silent MSI install from Temp, regular beaconing, upload-heavy traffic) outweighs the benign indicators. Verdict: True Positive, escalated to L2.


## Preserved evidence

| Record | Time (UTC) | Source | Object role | Observation |
| --- | --- | --- | --- | --- |
| ALT3-00004-E010 | 2026-09-09T11:17:08.000Z | Endpoint Sensor | Process image | Session root process created |
| ALT3-00004-E012 | 2026-09-09T11:31:34.000Z | Endpoint Sensor | Process image | Process start recorded |
| ALT3-00003-E015 | 2026-09-09T11:33:12.000Z | Endpoint Sensor | Process image | Child process created |
| ALT3-00003-E016 | 2026-09-09T11:33:53.000Z | Endpoint Sensor | Process image | Process start recorded |
| ALT3-00004-E014 | 2026-09-09T11:36:24.000Z | Firewall / Proxy | network | Outbound network connection |

## Case notes

No additional case notes.

## SLA history

- 2026-11-12T21:23:16.532Z: Critical, 1h, due 2026-11-12T22:23:16.532Z. Case created

## Simulated response log

- 2026-11-12T20:53:35.525Z: **Isolate Endpoint** on FIN-LT-001. Who: r.patel on FIN-LT-001
What: Repeated encoded PowerShell executions referencing a Temp script (Invoice_6070.ps1), each connecting to sync-0.test (192.0.2.1:443)
When: 09 Sept 2026, from about 11:31 to 11:39 UTC across the 27 records
Where: FIN-LT-001, outbound to sync-0.test
Why: Matches C2 beaconing or script-staging behavior (MITRE T1059.001 PowerShell, T1027 obfuscation). Evidence: encoded command, a Temp-folder script with an invoice-style name, and repeated connections to the same domain.

## Assessment feedback

Score: **61/100**. Scenario verdict: **True Positive**. Evidence coverage: **40%**.

Regular outbound connection intervals: The correlated session, execution and follow-on activity require escalation; no matching authorization was observed. Review the cited supporting records and qualifications.

### Evidence-by-conclusion

- **ALT3-00004-E012** (supporting, supports_verdict): msiexec.exe (PID 1028) references Invoice_2926.msi; image 15839c30e072… and artifact c63c2a6fc849… are distinct. Correlate ancestry and the artifact; a valid interpreter signature does not establish authorization.
- **ALT3-00004-E008** (supporting, supports_verdict): r.patel: Successful authentication, outcome Success, at 2026-09-09T11:38:10.000Z. Compare the baseline, session and device continuity before attributing activity.
- **ALT3-00004-E014** (supporting, supports_verdict): 10.40.1.10 → 192.0.2.1:443, Allowed; DNS record ALT3-00004-E013 resolves sync-0.test. A connection or reputation score alone does not prove intent; correlate process and destination.
- **ALT3-00004-E017** (supporting, supports_verdict): Invoice_2926.msi has SHA256 c63c2a6fc849c0170674fc5b87574a458c6bd46737c233a3a74c044d46d35c72; provider observations describe this object separately from the interpreter. Keep attachment, payload and image identities separate and corroborate provider observations with telemetry.
- **ALT3-00004-E004** (qualifying, qualifies_conclusion): Asset and account baseline snapshot: normal endpoint FIN-LT-001, country United Kingdom. Baseline context is a comparison point; validate unusual activity and absence of a matching approved change.

## Raw evidence

### ALT3-00004-E010

````json
{
  "id": "ALT3-00004-E010",
  "alert_id": "ALT3-00004",
  "incident_id": "INC-2026-0001",
  "timestamp": "2026-09-09T11:17:08.000Z",
  "kind": "process",
  "source": "Endpoint Sensor",
  "event_id": 4688,
  "user": "r.patel",
  "host": "FIN-LT-001",
  "source_ip": "192.0.2.1",
  "destination_ip": "10.40.1.10",
  "domain": "sync-0.test",
  "hash": "db005ebf059bcccf8afc5bd740d9283cee85a18d24bb90d95e5b64f24dade036",
  "process_name": "explorer.exe",
  "message": "Session root process created",
  "severity": "Critical",
  "data": {
    "pid": 1000,
    "ppid": 640,
    "name": "explorer.exe",
    "path": "C:\\Windows\\explorer.exe",
    "commandLine": "C:\\Windows\\explorer.exe",
    "signature": "Publisher signature valid",
    "user": "r.patel",
    "sha256": "db005ebf059bcccf8afc5bd740d9283cee85a18d24bb90d95e5b64f24dade036",
    "startTime": "2026-09-09T11:17:08.000Z",
    "connections": [],
    "imageSHA256": "db005ebf059bcccf8afc5bd740d9283cee85a18d24bb90d95e5b64f24dade036",
    "objectRole": "Process image"
  }
}
````

### ALT3-00004-E012

````json
{
  "id": "ALT3-00004-E012",
  "alert_id": "ALT3-00004",
  "incident_id": "INC-2026-0001",
  "timestamp": "2026-09-09T11:31:34.000Z",
  "kind": "process",
  "source": "Endpoint Sensor",
  "event_id": 4688,
  "user": "r.patel",
  "host": "FIN-LT-001",
  "source_ip": "192.0.2.1",
  "destination_ip": "10.40.1.10",
  "domain": "sync-0.test",
  "hash": "15839c30e072a119e9dc442ca3b5186968812fa0a2ae824c9cabb0490127d47c",
  "process_name": "msiexec.exe",
  "message": "Process start recorded",
  "severity": "Critical",
  "data": {
    "pid": 1028,
    "ppid": 1012,
    "name": "msiexec.exe",
    "path": "C:\\Windows\\System32\\msiexec.exe",
    "commandLine": "msiexec.exe /i \"C:\\Users\\r.patel\\AppData\\Local\\Temp\\Invoice_2926.msi\" /qn",
    "signature": "Publisher signature valid",
    "user": "r.patel",
    "sha256": "15839c30e072a119e9dc442ca3b5186968812fa0a2ae824c9cabb0490127d47c",
    "startTime": "2026-09-09T11:31:34.000Z",
    "integrity": "Medium",
    "connections": [
      {
        "remoteIP": "192.0.2.1",
        "remotePort": 443,
        "domain": "sync-0.test"
      }
    ],
    "rawBehavior": "Correlate the process image, referenced artifact and activity under this PID.",
    "imageSHA256": "15839c30e072a119e9dc442ca3b5186968812fa0a2ae824c9cabb0490127d47c",
    "objectRole": "Process image",
    "artifactSHA256": "c63c2a6fc849c0170674fc5b87574a458c6bd46737c233a3a74c044d46d35c72",
    "artifactPath": "C:\\Users\\r.patel\\AppData\\Local\\Temp\\Invoice_2926.msi",
    "artifactRole": "Referenced artifact"
  }
}
````

### ALT3-00003-E015

````json
{
  "id": "ALT3-00003-E015",
  "alert_id": "ALT3-00003",
  "incident_id": "INC-2026-0001",
  "timestamp": "2026-09-09T11:33:12.000Z",
  "kind": "process",
  "source": "Endpoint Sensor",
  "event_id": 4688,
  "user": "r.patel",
  "host": "FIN-LT-001",
  "source_ip": "192.0.2.1",
  "destination_ip": "10.40.1.10",
  "domain": "sync-0.test",
  "hash": "db005ebf059bcccf8afc5bd740d9283cee85a18d24bb90d95e5b64f24dade036",
  "process_name": "explorer.exe",
  "message": "Child process created",
  "severity": "High",
  "data": {
    "pid": 1012,
    "ppid": 1000,
    "name": "explorer.exe",
    "path": "C:\\Windows\\explorer.exe",
    "commandLine": "C:\\Windows\\explorer.exe",
    "signature": "Publisher signature valid",
    "user": "r.patel",
    "sha256": "db005ebf059bcccf8afc5bd740d9283cee85a18d24bb90d95e5b64f24dade036",
    "startTime": "2026-09-09T11:33:12.000Z",
    "connections": [],
    "imageSHA256": "db005ebf059bcccf8afc5bd740d9283cee85a18d24bb90d95e5b64f24dade036",
    "objectRole": "Process image"
  }
}
````

### ALT3-00003-E016

````json
{
  "id": "ALT3-00003-E016",
  "alert_id": "ALT3-00003",
  "incident_id": "INC-2026-0001",
  "timestamp": "2026-09-09T11:33:53.000Z",
  "kind": "process",
  "source": "Endpoint Sensor",
  "event_id": 4688,
  "user": "r.patel",
  "host": "FIN-LT-001",
  "source_ip": "192.0.2.1",
  "destination_ip": "10.40.1.10",
  "domain": "sync-0.test",
  "hash": "84a1dddf6245c7cb40281d0bf5760db68cfab02c977e30b20119b8fea6542d6b",
  "process_name": "powershell.exe",
  "message": "Process start recorded",
  "severity": "High",
  "data": {
    "pid": 1028,
    "ppid": 1012,
    "name": "powershell.exe",
    "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "commandLine": "powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAFMATwBDACAAbABhAGIAIABzAGkAbQB1AGwAYQB0AGkAbwBuACIA",
    "signature": "Publisher signature valid",
    "user": "r.patel",
    "sha256": "84a1dddf6245c7cb40281d0bf5760db68cfab02c977e30b20119b8fea6542d6b",
    "startTime": "2026-09-09T11:33:53.000Z",
    "integrity": "Medium",
    "connections": [
      {
        "remoteIP": "192.0.2.1",
        "remotePort": 443,
        "domain": "sync-0.test"
      }
    ],
    "rawBehavior": "Correlate the process image, referenced artifact and activity under this PID.",
    "imageSHA256": "84a1dddf6245c7cb40281d0bf5760db68cfab02c977e30b20119b8fea6542d6b",
    "objectRole": "Process image",
    "artifactSHA256": "30ffdb40f348e79851393b58bdcc9569cf58d65a99c40c171398015b04dc3823",
    "artifactPath": "C:\\Users\\r.patel\\AppData\\Local\\Temp\\Invoice_6070.ps1",
    "artifactRole": "Referenced artifact"
  }
}
````

### ALT3-00004-E014

````json
{
  "id": "ALT3-00004-E014",
  "alert_id": "ALT3-00004",
  "incident_id": "INC-2026-0001",
  "timestamp": "2026-09-09T11:36:24.000Z",
  "kind": "network",
  "source": "Firewall / Proxy",
  "event_id": 0,
  "user": "r.patel",
  "host": "FIN-LT-001",
  "source_ip": "10.40.1.10",
  "destination_ip": "192.0.2.1",
  "domain": "sync-0.test",
  "hash": "15839c30e072a119e9dc442ca3b5186968812fa0a2ae824c9cabb0490127d47c",
  "process_name": "msiexec.exe",
  "message": "Outbound network connection",
  "severity": "Critical",
  "data": {
    "sourcePort": 53373,
    "destinationPort": 443,
    "protocol": "TLS",
    "bytesSent": 124574,
    "bytesReceived": 40264,
    "duration": 19,
    "direction": "Outbound",
    "firewallAction": "Allowed",
    "process": "msiexec.exe",
    "pid": 1028,
    "hostname": "FIN-LT-001",
    "sni": "sync-0.test",
    "url": "https://sync-0.test/session/0",
    "proxyCategory": "Uncategorized",
    "httpMethod": "GET",
    "statusCode": 200,
    "intervalSeconds": 113,
    "connectionCount": 53,
    "sessionId": "S-0-3",
    "sampledBytes": 124574,
    "imageSHA256": "15839c30e072a119e9dc442ca3b5186968812fa0a2ae824c9cabb0490127d47c"
  }
}
````
