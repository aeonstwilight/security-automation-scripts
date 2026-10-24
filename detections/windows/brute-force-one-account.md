# Brute force against one account from one source

| | |
|---|---|
| ID | WIN-016 |
| ATT&CK | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing |
| Data needed | Security 4625 on servers and DCs, and 4771 on domain controllers |
| Severity | Medium |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Guessing many passwords for one account shows as repeated wrong-password failures for that account from one source: 4625 with `0xc000006a`, or 4771 with `0x18` for Kerberos. Unknown user names are left out (that is the spray pattern, WIN-015).

Whether the guessing then succeeded is the first thing to check when it fires. A "failures followed by a success" condition is possible in both Splunk and KQL, but it is kept out of the alert so a burst is still reported when the success happens later or from another protocol.

## Splunk

Field names differ between the classic and XML Windows event formats, so both are checked.

```spl
index=<windows_index>
    ( (EventCode=4625 (Sub_Status="0xc000006a" OR SubStatus="0xc000006a"))
   OR (EventCode=4771 (Failure_Code="0x18" OR Status="0x18")) )
| eval src = replace(src, "^::ffff:", "")
| where isnotnull(src) AND NOT src IN ("-", "", "127.0.0.1", "::1")
| bin _time span=30m
| stats count as failures by _time, src, user
| where failures >= 10
```

## Microsoft Sentinel

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where (EventID == 4625 and SubStatus =~ "0xc000006a")
     or (EventID == 4771 and Status =~ "0x18")
| extend Source = trim_start(@"::ffff:", IpAddress)
| where isnotempty(Source) and Source !in ("-", "127.0.0.1", "::1")
| summarize Failures = count() by Source, TargetUserName, bin(TimeGenerated, 30m)
| where Failures >= 10
```

## Elastic

ES|QL.

```esql
FROM logs-system.security-*
| WHERE (event.code == "4625" AND TO_LOWER(winlog.event_data.SubStatus) == "0xc000006a")
     OR (event.code == "4771" AND TO_LOWER(winlog.event_data.Status) == "0x18")
| WHERE source.ip IS NOT NULL AND NOT CIDR_MATCH(source.ip, "127.0.0.0/8", "::1/128")
| STATS failures = COUNT(*) BY source.ip, winlog.event_data.TargetUserName, bucket = BUCKET(@timestamp, 30 minutes)
| WHERE failures >= 10
```

## False positives

- A service, script or mapped drive retrying an old password after a password change.
- A user's phone or laptop retrying cached credentials after a password change.
- Many users behind one NAT or VPN address mistyping a shared account's password.

## Blind spots

- Slow guessing (fewer than 10 per 30 minutes) and guessing from many sources.
- Fixed 30-minute buckets: a burst split across a boundary can stay under the threshold in both.
- Guessing against cloud identity providers (Entra ID, ADFS).

## Validate

From one lab host, fail a logon for the same account ten or more times:

```cmd
for /L %i in (1,1,10) do net use \\<server>\IPC$ /user:LAB\testuser WrongPassword%i & net use \\<server>\IPC$ /delete
```

## Respond

Search for a 4624 (or 4768) for the same account from the same source during and after the burst; if there is one, treat the account as compromised. A recent password change (4723/4724) with failures from the user's own devices points to stale credentials. Otherwise block the source and escalate.
