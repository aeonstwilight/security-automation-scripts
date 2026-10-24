# Password spray from one source

| | |
|---|---|
| ID | WIN-015 |
| ATT&CK | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying |
| Data needed | Security 4625 on servers and DCs, and 4771 on domain controllers |
| Severity | Medium |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

A spray tries one or two passwords against many accounts to stay under the lockout limit. It shows as one source failing as many different users in a short time: NTLM and other logons as 4625 with a wrong password (`0xc000006a`) or unknown user (`0xc0000064`), and Kerberos spraying (kerbrute) as 4771 with pre-authentication failed (`0x18`). Local logons (no source address, loopback) are left out.

4771 writes the address as `::ffff:<IPv4>`. The queries strip that prefix, so NTLM and Kerberos failures from one host count together.

## Splunk

Field names differ between the classic and XML Windows event formats, so both are checked.

```spl
index=<windows_index>
    ( (EventCode=4625 (Sub_Status IN ("0xc000006a", "0xc0000064") OR SubStatus IN ("0xc000006a", "0xc0000064")))
   OR (EventCode=4771 (Failure_Code="0x18" OR Status="0x18")) )
| eval src = replace(src, "^::ffff:", "")
| where isnotnull(src) AND NOT src IN ("-", "", "127.0.0.1", "::1")
| bin _time span=30m
| stats dc(user) as users values(user) as targets count by _time, src
| where users >= 10
```

## Microsoft Sentinel

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where (EventID == 4625 and SubStatus in~ ("0xc000006a", "0xc0000064"))
     or (EventID == 4771 and Status =~ "0x18")
| extend Source = trim_start(@"::ffff:", IpAddress)
| where isnotempty(Source) and Source !in ("-", "127.0.0.1", "::1")
| summarize Users = dcount(TargetUserName), Targets = make_set(TargetUserName, 50), Failures = count()
    by Source, bin(TimeGenerated, 30m)
| where Users >= 10
```

## Elastic

ES|QL. The Windows integration stores the source as an IP field and drops the `::ffff:` prefix itself.

```esql
FROM logs-system.security-*
| WHERE (event.code == "4625" AND TO_LOWER(winlog.event_data.SubStatus) IN ("0xc000006a", "0xc0000064"))
     OR (event.code == "4771" AND TO_LOWER(winlog.event_data.Status) == "0x18")
| WHERE source.ip IS NOT NULL AND NOT CIDR_MATCH(source.ip, "127.0.0.0/8", "::1/128")
| STATS users = COUNT_DISTINCT(winlog.event_data.TargetUserName), targets = VALUES(winlog.event_data.TargetUserName)
    BY source.ip, bucket = BUCKET(@timestamp, 30 minutes)
| WHERE users >= 10
```

## False positives

- An application or script trying many accounts with stale credentials.
- Vulnerability scanners with credentialed checks for many accounts.
- Many users failing behind one NAT, proxy or VPN address.

Set the threshold above your noisiest legitimate source, allowlist known scanners by source, then lower it.

## Blind spots

- Slow sprays (fewer than 10 users per 30 minutes per source) and sprays spread over many sources.
- Fixed 30-minute buckets: a spray split across a bucket boundary can stay under the threshold in both.
- Spraying against cloud identity providers (Entra ID, ADFS), which don't write these events.

## Validate

From one lab host, fail a logon as ten or more different users within a few minutes:

```cmd
for /L %i in (1,1,10) do net use \\<dc>\IPC$ /user:LAB\user%i WrongPassword1 & net use \\<dc>\IPC$ /delete
```

## Respond

Check whether any of the target accounts then logged on successfully from the same source (4624, 4768): treat those as compromised and reset them. Resolve the source; if it isn't a known scanner or misconfigured service, block or isolate it.
