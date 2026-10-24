# PsExec service installed

| | |
|---|---|
| ID | WIN-017 |
| ATT&CK | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) Remote Services: SMB/Windows Admin Shares, [T1569.002](https://attack.mitre.org/techniques/T1569/002/) System Services: Service Execution |
| Data needed | System 7045 (service installed) |
| Severity | Medium |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Sysinternals PsExec copies `PSEXESVC.exe` to `ADMIN$` and installs it as a service on the target, both for lateral movement and to run commands as SYSTEM locally. Ransomware operators push it to many hosts in minutes. The service name `PSEXESVC` or an image path ending in `\PSEXESVC.exe` identifies it.

## Splunk

Field names differ between the classic and XML Windows event formats, so both are checked.

```spl
index=<windows_index> EventCode=7045
    (Service_Name="PSEXESVC" OR ServiceName="PSEXESVC"
     OR Service_File_Name="*\\PSEXESVC.exe" OR ImagePath="*\\PSEXESVC.exe")
| stats count min(_time) as first_seen by dest
| convert ctime(first_seen)
```

To see a fan-out across hosts, add `| bin _time span=15m | stats dc(dest) as hosts values(dest) by _time` instead.

## Microsoft Sentinel

The System log arrives in the `Event` table.

```kql
Event
| where TimeGenerated > ago(1h)
| where EventLog == "System" and EventID == 7045
| where EventData has "PSEXESVC"
| project TimeGenerated, Computer, RenderedDescription
```

## Elastic

```eql
any where event.code == "7045" and
  (winlog.event_data.ServiceName : "PSEXESVC" or winlog.event_data.ImagePath : "*\\PSEXESVC.exe")
```

## False positives

Administrators and IT tooling using PsExec for remote administration. Allowlist by source host (admin workstations, jump hosts) after finding it from the logon events, not by target.

## Blind spots

- Renamed PsExec (`psexec -r <name>`) changes both the service name and the image path. Its named pipes (`<name>-<host>-<pid>-stdin` and similar) are the way to catch it.
- PsExec look-alikes (Impacket `psexec.py`, PAExec, RemCom) install their own service names.

## Validate

From one lab host to another, as an administrator on the target:

```cmd
PsExec.exe \\<target> cmd /c whoami
```

## Respond

7045 doesn't record the source. Find the network logon (4624 type 3) on the target just before, then the commands run under `PSEXESVC.exe`. Check for PsExec on other hosts in the same window. Known admin use from a jump host can be closed; anything else is lateral movement.
