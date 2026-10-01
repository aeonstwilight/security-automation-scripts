# Command shell spawned by the WMI provider host

| | |
|---|---|
| ID | WIN-008 |
| ATT&CK | [T1047](https://attack.mitre.org/techniques/T1047/) Windows Management Instrumentation |
| Data needed | Process creation with parent process (Sysmon 1 or EDR) |
| Severity | Medium |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Remote execution through WMI, as done by `wmic /node:` and Impacket's wmiexec, runs the command as a child of `WmiPrvSE.exe` on the target. A shell or script host with that parent is the visible end of the technique.

## Splunk

```spl
| tstats summariesonly=true count min(_time) as first_seen
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name="WmiPrvSE.exe"
          Processes.process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "cscript.exe", "wscript.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(first_seen)
```

## Microsoft Sentinel

```kql
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "cscript.exe", "wscript.exe")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```

## False positives

Configuration management and monitoring agents use WMI heavily. Their command lines are repetitive, so allowlist by command-line pattern per tool.

## Validate

In a lab: `wmic /node:TARGET process call create "cmd.exe /c whoami"`.

## Respond

Find the source of the WMI connection with the matching network logon (4624 type 3) on the target at the same time.
