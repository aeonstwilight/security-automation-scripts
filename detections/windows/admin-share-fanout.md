# One source accessing admin shares on many hosts

| | |
|---|---|
| ID | WIN-006 |
| ATT&CK | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) Remote Services: SMB/Windows Admin Shares |
| Data needed | Security event 5140 (Audit File Share) from servers and workstations |
| Severity | High |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Tools that move laterally over SMB, including PsExec-style execution and many ransomware deployers, connect to `ADMIN$` or `C$` on each target. Administrators do this too, but rarely to many hosts in minutes.

## Splunk

Field names for the share differ between the classic and XML Windows event formats, so both are checked.

```spl
index=<windows_index> EventCode=5140
    (Share_Name="*ADMIN$" OR Share_Name="*C$" OR ShareName="*ADMIN$" OR ShareName="*C$")
| bin _time span=15m
| stats dc(dest) as hosts values(dest) as targets by _time, src, user
| where hosts >= 5
```

## Microsoft Sentinel

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 5140
| where ShareName endswith "ADMIN$" or ShareName endswith "C$"
| summarize Hosts = dcount(Computer), Targets = make_set(Computer, 25)
    by IpAddress, SubjectUserName, bin(TimeGenerated, 15m)
| where Hosts >= 5
```

## False positives

Software deployment, vulnerability scanners with credentialed scans, backup servers and admin jump hosts. Allowlist those by source address, and review the list when it changes.

## Blind spots

Event 5140 is only logged where "Audit File Share" is enabled, and it is high volume on file servers and domain controllers. If it is not collected everywhere, coverage is partial.

## Validate

From a lab workstation, as an admin: `dir \\HOST\C$` against five or more lab hosts within a few minutes.

## Respond

Identify the source host and the account. Check what was written to the shares and whether a service or scheduled task was created on the targets (7045, 4698).
