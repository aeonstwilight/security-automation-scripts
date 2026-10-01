# Office application spawning a shell or script host

| | |
|---|---|
| ID | WIN-009 |
| ATT&CK | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) User Execution: Malicious File, [T1059](https://attack.mitre.org/techniques/T1059/) Command and Scripting Interpreter |
| Data needed | Process creation with parent process (Sysmon 1 or EDR) |
| Severity | High |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Word, Excel, PowerPoint, Outlook and OneNote have little reason to launch a command shell or script host. When one does, a document or attachment is usually running code.

## Splunk

```spl
| tstats summariesonly=true count min(_time) as first_seen
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe")
          Processes.process_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(first_seen)
```

## Microsoft Sentinel

```kql
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

## False positives

Office add-ins and finance macros that shell out. These are specific to a team and a command line, so allowlist narrowly.

## Validate

In a lab, run a macro containing `Shell "cmd.exe /c whoami"`.

## Respond

Isolate the host, recover the document or email, and search mail logs for other recipients.
