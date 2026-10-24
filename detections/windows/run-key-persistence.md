# Run key value pointing to a script host, LOLBin or user-writable path

| | |
|---|---|
| ID | WIN-014 |
| ATT&CK | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| Data needed | Registry value set events with the value data (Sysmon 13, or EDR) |
| Severity | Medium |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Run keys are the most common persistence there is, and many legitimate programs use them, so an allowlist of writers never ends. This detection looks at what the value runs instead: a script host or LOLBin (PowerShell, pwsh, cmd, wscript, cscript, mshta, rundll32, regsvr32), or a program in a user-writable folder (`AppData\Roaming`, `Temp`, `Users\Public`, `ProgramData`, `Windows\Tasks`, `PerfLogs`). `AppData\Local` is left out on purpose: Teams, OneDrive, Slack and other per-user installers live there.

Covers Run, RunOnce, RunOnceEx, RunServices and `Policies\Explorer\Run`, in HKLM, HKCU and WOW6432Node.

## Splunk

CIM Endpoint data model.

```spl
| tstats summariesonly=true count min(_time) as first_seen
    from datamodel=Endpoint.Registry
    where Registry.registry_path IN ("*\\CurrentVersion\\Run*", "*\\Policies\\Explorer\\Run*")
          Registry.registry_value_data IN ("*powershell*", "*pwsh*", "*cmd.exe*", "*wscript*", "*cscript*", "*mshta*", "*rundll32*", "*regsvr32*",
              "*\\AppData\\Roaming\\*", "*\\Temp\\*", "*\\Users\\Public\\*", "*\\ProgramData\\*", "*\\Windows\\Tasks\\*", "*\\PerfLogs\\*")
    by Registry.dest, Registry.user, Registry.process_name, Registry.registry_path, Registry.registry_value_data
| `drop_dm_object_name(Registry)`
| convert ctime(first_seen)
```

## Microsoft Sentinel

```kql
DeviceRegistryEvents
| where TimeGenerated > ago(1h)
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"\CurrentVersion\Run" or RegistryKey has @"\Policies\Explorer\Run"
| where RegistryValueData matches regex @"(?i)powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|\\(AppData\\Roaming|Temp|Users\\Public|ProgramData|Windows\\Tasks|PerfLogs)\\"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
          RegistryKey, RegistryValueName, RegistryValueData
```

## Elastic

```eql
registry where
  registry.path : ("*\\CurrentVersion\\Run*", "*\\Policies\\Explorer\\Run*") and
  registry.data.strings : ("*powershell*", "*pwsh*", "*cmd.exe*", "*wscript*", "*cscript*", "*mshta*", "*rundll32*", "*regsvr32*",
                           "*\\AppData\\Roaming\\*", "*\\Temp\\*", "*\\Users\\Public\\*", "*\\ProgramData\\*", "*\\Windows\\Tasks\\*", "*\\PerfLogs\\*")
```

## False positives

- Software that starts a helper through rundll32, PowerShell or a script at logon.
- Per-user applications installed in `AppData\Roaming` or `ProgramData` (some updaters and chat clients).
- Installers that use RunOnce to finish setup from `Temp` after a reboot.

Allowlist locally by value name and data.

## Blind spots

- Payloads in `AppData\Local` (outside `Temp`) or under Program Files.
- Other autostart locations: Winlogon `Userinit`/`Shell`, Active Setup, services, scheduled tasks, the Startup folder.
- Offline hive edits, or a Sysmon config that doesn't log Run keys.

## Validate

In a lab VM:

```cmd
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v LabTest /d "powershell.exe -nop -c exit" /f
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v LabTest /f
```

## Respond

Read the value data in full (decode any encoded PowerShell), check which process wrote it, and check the target file's hash, signer and creation time. If it isn't a known product, delete the value, remove the payload and work out how it got there.
