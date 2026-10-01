# Account created and deleted within a day

| | |
|---|---|
| ID | WIN-005 |
| ATT&CK | [T1136.002](https://attack.mitre.org/techniques/T1136/002/) Create Account: Domain Account, [T1070.009](https://attack.mitre.org/techniques/T1070/009/) Clear Persistence |
| Data needed | Domain controller Security log, events 4720 and 4726 |
| Severity | Medium |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

An account that exists for a few hours is rarely legitimate. It fits an attacker who creates an account, uses it, and removes it to clean up.

## Splunk

```spl
index=<windows_index> EventCode IN (4720, 4726) earliest=-24h
| stats min(eval(if(EventCode=4720, _time, null()))) as created
        max(eval(if(EventCode=4726, _time, null()))) as deleted
        values(src_user) as actors
    by user
| where isnotnull(created) AND isnotnull(deleted) AND deleted > created
| eval lifetime_minutes = round((deleted - created) / 60, 1)
| convert ctime(created) ctime(deleted)
```

## Microsoft Sentinel

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID in (4720, 4726)
| summarize Created = minif(TimeGenerated, EventID == 4720),
            Deleted = maxif(TimeGenerated, EventID == 4726),
            Actors = make_set(SubjectUserName)
    by TargetUserName
| where isnotnull(Created) and isnotnull(Deleted) and Deleted > Created
| extend LifetimeMinutes = datetime_diff("minute", Deleted, Created)
```

## False positives

Provisioning mistakes corrected right away. These show a lifetime of a minute or two and a known administrator as the actor.

## Validate

Create a test account in a lab domain, wait ten minutes, delete it.

## Respond

Find what the account did while it existed: logons (4624), group changes (4728, 4732, 4756) and any resources it touched.
