# One account authenticating to many hosts

| | |
|---|---|
| ID | WIN-007 |
| ATT&CK | [T1021](https://attack.mitre.org/techniques/T1021/) Remote Services, [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts |
| Data needed | Windows logon events mapped to the CIM Authentication data model |
| Severity | Medium |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

A stolen credential being tested or used across the estate shows up as one account, from one source, logging on to an unusual number of machines.

## Splunk

```spl
| tstats summariesonly=true dc(Authentication.dest) as hosts values(Authentication.dest) as targets
    from datamodel=Authentication
    where Authentication.action=success Authentication.user!="*$" Authentication.user!="ANONYMOUS LOGON"
    by Authentication.src, Authentication.user, _time span=15m
| `drop_dm_object_name(Authentication)`
| where hosts >= 10
```

## Microsoft Sentinel

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624 and LogonType == 3
| where TargetUserName !endswith "$" and TargetUserName != "ANONYMOUS LOGON"
| summarize Hosts = dcount(Computer), Targets = make_set(Computer, 25)
    by IpAddress, TargetUserName, bin(TimeGenerated, 15m)
| where Hosts >= 10
```

## False positives

Service accounts for monitoring, patching, scanning and backup. This detection needs a baseline: start the threshold above your noisiest legitimate account, then allowlist the known service accounts and lower it.

## Validate

From one lab host, authenticate to ten or more others with the same account, for example with `net use \\HOST\IPC$`.

## Respond

Check whether the source host is one the account normally uses. If not, reset the credential and review the source host for compromise.
