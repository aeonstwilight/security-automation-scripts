# LSASS opened with memory read access

| | |
|---|---|
| ID | WIN-012 |
| ATT&CK | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) OS Credential Dumping: LSASS Memory |
| Data needed | Process access to `lsass.exe` (Sysmon 10 with a config that logs it, or Defender for Endpoint) |
| Severity | High |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Reading LSASS memory is how Mimikatz, ProcDump, `comsvcs.dll MiniDump`, Task Manager "Create dump file" and most in-memory tools get credentials. Each needs a handle with `PROCESS_VM_READ` (0x10). The main query matches the common access masks that include it; a second query catches tools that ask for less (PPLdump uses `0x1000`) when they run from a user, temp or network path.

## Splunk

```spl
index=<windows_index> source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
    TargetImage="*\\lsass.exe"
    GrantedAccess IN ("0x1010", "0x1410", "0x1438", "0x143a", "0x1f0fff", "0x1f1fff", "0x1f3fff", "0x1fffff")
    NOT SourceImage IN ("C:\\Windows\\System32\\services.exe", "C:\\Windows\\System32\\wininit.exe", "C:\\Windows\\System32\\csrss.exe")
| stats count min(_time) as first_seen values(GrantedAccess) as access values(CallTrace) as call_trace
    by host, SourceImage, SourceUser
| convert ctime(first_seen)
```

Other masks from user, temp or network paths:

```spl
index=<windows_index> source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
    TargetImage="*\\lsass.exe"
    (SourceImage="*\\Users\\*" OR SourceImage="*\\AppData\\*" OR SourceImage="*\\Temp\\*"
     OR SourceImage="*\\ProgramData\\*" OR SourceImage="*\\Downloads\\*" OR SourceImage="\\\\*")
    NOT GrantedAccess IN ("0x1010", "0x1410", "0x1438", "0x143a", "0x1f0fff", "0x1f1fff", "0x1f3fff", "0x1fffff")
| stats count min(_time) as first_seen values(GrantedAccess) as access by host, SourceImage, SourceUser
| convert ctime(first_seen)
```

## Microsoft Sentinel

Defender for Endpoint records LSASS handle requests as `OpenProcessApiCall` events, with the access mask in `AdditionalFields`. These events are sampled, so this is weaker than Sysmon 10; check what your tenant records before relying on it.

```kql
DeviceEvents
| where TimeGenerated > ago(1h)
| where ActionType == "OpenProcessApiCall" and FileName =~ "lsass.exe"
| extend DesiredAccess = tolong(parse_json(AdditionalFields).DesiredAccess)
| where binary_and(DesiredAccess, 0x10) == 0x10
| where InitiatingProcessFolderPath !in~ (@"c:\windows\system32\services.exe", @"c:\windows\system32\wininit.exe", @"c:\windows\system32\csrss.exe")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, DesiredAccess
```

## Elastic

```eql
any where event.code == "10" and
  winlog.event_data.TargetImage : "*\\lsass.exe" and
  winlog.event_data.GrantedAccess : ("0x1010", "0x1410", "0x1438", "0x143a", "0x1f0fff", "0x1f1fff", "0x1f3fff", "0x1fffff") and
  not process.executable : ("C:\\Windows\\System32\\services.exe", "C:\\Windows\\System32\\wininit.exe", "C:\\Windows\\System32\\csrss.exe")
```

## False positives

- AV, EDR and backup agents that scan or snapshot LSASS. Allowlist by exact path and signer, after checking the history across the fleet.
- Administrators creating LSASS dumps for troubleshooting.
- Monitoring or inventory tools that read process memory.

## Blind spots

- Read masks not in the list. The list is a starting point, not a full bitmask check (the Sentinel query does check the bit).
- Tools running from `C:\Windows`, Program Files or another drive with a non-read mask.
- Hosts whose Sysmon config doesn't log process access to `lsass.exe`. Check this before trusting silence.

## Validate

In a lab VM, as administrator, then delete the dump:

```powershell
$p = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $p C:\Windows\Temp\l.dmp full
```

## Respond

Pivot from the source process to its creation event (command line, parent, user) and look for a `.dmp` file written by it. Unless it is a known agent at its expected path, assume credentials on the host are exposed and reset the accounts with active sessions there.
