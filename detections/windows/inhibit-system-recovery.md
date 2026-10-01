# Shadow copy deletion and recovery tampering

| | |
|---|---|
| ID | WIN-001 |
| ATT&CK | [T1490](https://attack.mitre.org/techniques/T1490/) Inhibit System Recovery |
| Data needed | Process creation with command line (Sysmon 1, Security 4688, or EDR) |
| Severity | High |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Almost every ransomware family deletes shadow copies, wipes the backup catalog and disables automatic repair before it encrypts. The commands are few, rarely used legitimately, and run before the damage is done.

## Splunk

CIM Endpoint data model.

```spl
| tstats summariesonly=true count min(_time) as first_seen max(_time) as last_seen
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe", "powershell.exe", "pwsh.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| eval process_name = lower(process_name)
| where (process_name="vssadmin.exe" AND match(process, "(?i)delete\s+shadows|resize\s+shadowstorage"))
     OR (process_name="wmic.exe" AND match(process, "(?i)shadowcopy.+delete"))
     OR (process_name="wbadmin.exe" AND match(process, "(?i)delete\s+(catalog|systemstatebackup|backup)"))
     OR (process_name="bcdedit.exe" AND match(process, "(?i)recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures"))
     OR (process_name IN ("powershell.exe", "pwsh.exe") AND match(process, "(?i)win32_shadowcopy") AND match(process, "(?i)delete|remove-"))
| convert ctime(first_seen) ctime(last_seen)
```

## Microsoft Sentinel

```kql
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine matches regex @"(?i)delete\s+shadows|resize\s+shadowstorage")
     or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
     or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete" and ProcessCommandLine has_any ("catalog", "systemstatebackup", "backup"))
     or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled", "bootstatuspolicy"))
     or (FileName in~ ("powershell.exe", "pwsh.exe") and ProcessCommandLine has "Win32_ShadowCopy" and ProcessCommandLine has_any ("Delete", "Remove-WmiObject", "Remove-CimInstance"))
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

## Elastic

```eql
process where event.type == "start" and
  (
    (process.name : "vssadmin.exe" and process.args : ("delete", "resize") and process.args : ("shadows", "shadowstorage")) or
    (process.name : "wmic.exe" and process.args : "shadowcopy" and process.args : "delete") or
    (process.name : "wbadmin.exe" and process.args : "delete" and process.args : ("catalog", "systemstatebackup", "backup")) or
    (process.name : "bcdedit.exe" and process.args : ("recoveryenabled", "bootstatuspolicy"))
  )
```

## False positives

- Backup software managing its own shadow copies. Allowlist by parent process and host.
- Imaging and deployment task sequences calling `bcdedit`.
- Administrators freeing disk space.

Do not exclude by user account alone. Attackers run these as a domain admin or SYSTEM.

## Blind spots

Payloads that delete shadow copies through the WMI or VSS COM interfaces create no child process. Renamed binaries evade name matching; use the original file name from the PE header where the telemetry has it.

## Validate

In an isolated lab VM with nothing you need to recover:

```cmd
vssadmin.exe delete shadows /all /quiet
bcdedit.exe /set {default} recoveryenabled no
```

Restore afterwards with `bcdedit.exe /set {default} recoveryenabled yes`.

## Respond

Treat a true positive as an incident in progress. Isolate the host, then trace the parent process chain and where the account has authenticated in the last 24 hours.
