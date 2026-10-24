# SAM or SECURITY hive, or NTDS.dit, copied for offline extraction

| | |
|---|---|
| ID | WIN-011 |
| ATT&CK | [T1003.002](https://attack.mitre.org/techniques/T1003/002/) Security Account Manager, [T1003.003](https://attack.mitre.org/techniques/T1003/003/) NTDS, [T1003.004](https://attack.mitre.org/techniques/T1003/004/) LSA Secrets |
| Data needed | Process creation with command line (Sysmon 1, Security 4688, or EDR) |
| Severity | High |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

The built-in tools are enough to take the credential stores offline: `reg save` of the SAM, SECURITY and SYSTEM hives (local hashes, LSA secrets, cached domain logons, and the boot key to decrypt them), `ntdsutil ifm` or `esentutl /vss` for the AD database, or a plain copy out of a shadow copy. Four patterns:

- `reg.exe` with `save` or `export` of `HKLM\SAM` or `HKLM\SECURITY` (any subkey), or of the whole `HKLM\SYSTEM` hive
- `ntdsutil.exe` with `ifm`
- `esentutl.exe` with `/vss` and `config\sam`, `config\security`, `config\system` or `ntds.dit`
- any command line with `HarddiskVolumeShadowCopy` and one of those files (`copy` is a cmd built-in, so there is no binary condition)

SYSTEM is matched only as the whole hive or file, so exports of single service keys and paths under `config\systemprofile` stay quiet. The queries use `.` for the path separator to keep the regexes readable.

## Splunk

CIM Endpoint data model.

```spl
| tstats summariesonly=true count min(_time) as first_seen
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("reg.exe", "ntdsutil.exe", "esentutl.exe") OR Processes.process="*HarddiskVolumeShadowCopy*")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| eval process_name = lower(process_name)
| where (process_name="reg.exe" AND match(process, "(?i)\s(save|export)\s")
         AND match(process, "(?i)(hklm|hkey_local_machine).(sam|security)|(hklm|hkey_local_machine).system(\s|\"|$)"))
     OR (process_name="ntdsutil.exe" AND match(process, "(?i)ifm"))
     OR (process_name="esentutl.exe" AND match(process, "(?i)[/-]vss")
         AND match(process, "(?i)config.(sam|security)|config.system(\s|\"|$)|ntds\.dit"))
     OR (match(process, "(?i)HarddiskVolumeShadowCopy")
         AND match(process, "(?i)ntds\.dit|config.(sam|security)|config.system(\s|\"|$)"))
| convert ctime(first_seen)
```

## Microsoft Sentinel

```kql
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where (FileName =~ "reg.exe"
         and ProcessCommandLine matches regex @"(?i)\s(save|export)\s"
         and ProcessCommandLine matches regex @"(?i)(hklm|hkey_local_machine).(sam|security)|(hklm|hkey_local_machine).system(\s|""|$)")
     or (FileName =~ "ntdsutil.exe" and ProcessCommandLine has "ifm")
     or (FileName =~ "esentutl.exe"
         and ProcessCommandLine matches regex @"(?i)[/-]vss"
         and ProcessCommandLine matches regex @"(?i)config.(sam|security)|config.system(\s|""|$)|ntds\.dit")
     or (ProcessCommandLine has "HarddiskVolumeShadowCopy"
         and ProcessCommandLine matches regex @"(?i)ntds\.dit|config.(sam|security)|config.system(\s|""|$)")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

## Elastic

```eql
process where event.type == "start" and
  (
    (process.name : "reg.exe" and process.args : ("save", "export") and
     process.args : ("hklm\\sam*", "hklm\\security*", "hklm\\system",
                     "hkey_local_machine\\sam*", "hkey_local_machine\\security*", "hkey_local_machine\\system")) or
    (process.name : "ntdsutil.exe" and process.command_line : "*ifm*") or
    (process.name : "esentutl.exe" and process.args : ("/vss", "-vss") and
     process.command_line : ("*config\\sam*", "*config\\security*", "*config\\system", "*config\\system *", "*config\\system\"*", "*ntds.dit*")) or
    (process.command_line : "*HarddiskVolumeShadowCopy*" and
     process.command_line : ("*\\ntds.dit*", "*\\config\\sam*", "*\\config\\security*", "*\\config\\system", "*\\config\\system *", "*\\config\\system\"*"))
  )
```

## False positives

- Backup or imaging tools copying hives or the AD database (a known product and service account).
- Administrators creating an IFM copy with `ntdsutil` to promote a domain controller from media.
- Forensic or incident response collection of registry hives.

Allowlist by exact command line, parent and account.

## Blind spots

- In-memory extraction (Mimikatz `lsadump::sam`, `lsadump::secrets`) and raw-disk readers (Invoke-NinjaCopy).
- `diskshadow /s script.txt`, which hides the commands in a file.
- Renamed `reg`, `ntdsutil` or `esentutl`. Match on the original file name from the PE header where the telemetry has it.
- Remote hive access over the Remote Registry service (`secretsdump` against a remote host) starts no process on the target; look for `winreg` named-pipe access (5145) instead.

## Validate

In a lab VM:

```cmd
reg save HKLM\SAM C:\Windows\Temp\s.hiv
reg save HKLM\SYSTEM C:\Windows\Temp\y.hiv
del C:\Windows\Temp\s.hiv C:\Windows\Temp\y.hiv
```

## Respond

Check where the copies were written and whether SYSTEM was taken in the same few minutes (SAM or SECURITY can't be decrypted without it). Treat an unexplained copy as credential compromise: rotate local admin passwords (LAPS), the affected domain accounts, and after an NTDS copy reset `krbtgt` twice.
