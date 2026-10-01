# Bulk Active Directory account deletion

| | |
|---|---|
| ID | WIN-004 |
| ATT&CK | [T1531](https://attack.mitre.org/techniques/T1531/) Account Access Removal |
| Data needed | Domain controller Security log, event 4726 (Audit User Account Management) |
| Severity | High |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Help desks delete accounts every day, so an alert on every 4726 is noise. Many deletions by one actor in a short window is either a cleanup project or someone removing access on the way out.

## Splunk

```spl
index=<windows_index> EventCode=4726
| bin _time span=10m
| stats count as deleted values(user) as deleted_accounts by _time, src_user
| where deleted >= 5
```

## Microsoft Sentinel

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4726
| summarize Deleted = count(), Accounts = make_set(TargetUserName, 50)
    by SubjectUserName, bin(TimeGenerated, 10m)
| where Deleted >= 5
```

## False positives

Scheduled offboarding jobs. Exclude the job by account and time window; do not raise the threshold for everyone.

## Validate

Create and delete five test accounts in a lab domain within a few minutes.

## Respond

Confirm with the actor's manager or the identity team. If unexpected, disable the actor account and restore the deleted objects from the AD Recycle Bin.
