# Windows event log cleared

| | |
|---|---|
| ID | WIN-018 |
| ATT&CK | [T1685.005](https://attack.mitre.org/techniques/T1685/005/) Clear Windows Event Logs |
| Data needed | Security 1102 and System 104 |
| Severity | High |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Nothing in normal operation clears an event log: rotation and auto-archiving don't, only an explicit clear (`wevtutil cl`, `Clear-EventLog`, Event Viewer, or the EventLog RPC interface remotely). Clearing the Security log writes 1102; clearing any other log (System, Sysmon, PowerShell) writes System 104 from the `Microsoft-Windows-Eventlog` provider. The provider filter matters: RdpCoreTS reuses event ID 104 for something unrelated.

## Splunk

```spl
index=<windows_index>
    ( (EventCode=1102 source IN ("WinEventLog:Security", "XmlWinEventLog:Security"))
   OR (EventCode=104 source IN ("WinEventLog:System", "XmlWinEventLog:System")
       "Microsoft-Windows-Eventlog") )
| stats count min(_time) as first_seen values(EventCode) as event_codes values(Channel) as channel by dest, user
| convert ctime(first_seen)
```

## Microsoft Sentinel

```kql
union
    (SecurityEvent
     | where TimeGenerated > ago(1h)
     | where EventID == 1102
     | project TimeGenerated, Computer, Account = SubjectUserName, Log = "Security"),
    (Event
     | where TimeGenerated > ago(1h)
     | where EventLog == "System" and EventID == 104 and Source == "Microsoft-Windows-Eventlog"
     | project TimeGenerated, Computer, Account = UserName, Log = RenderedDescription)
```

## Elastic

```eql
any where
  (event.code == "1102" and winlog.channel : "Security") or
  (event.code == "104" and winlog.channel : "System" and winlog.provider_name : "Microsoft-Windows-Eventlog")
```

## False positives

- Administrators clearing a log during troubleshooting or before imaging a machine.
- Lab and test environments that reset logs between runs.

## Blind spots

- Tampering without a clear: stopping the EventLog service, changing audit policy (4719), shrinking the log, patching the service in memory.
- Clears that never reach the SIEM because the forwarder was stopped first. A host that goes quiet needs a separate missing-logs check.

## Validate

In a lab VM, as administrator:

```cmd
wevtutil cl Security
wevtutil cl "Windows PowerShell"
```

## Respond

Pivot on the subject logon ID to the 4624: a network logon means the clear came from another host. Pull everything forwarded from the host in the hour before, and search for clears on other hosts by the same account. Unless it is a documented admin action, treat it as anti-forensics during an intrusion.
