# WMI event subscription bound to a command line or script consumer

| | |
|---|---|
| ID | WIN-013 |
| ATT&CK | [T1546.003](https://attack.mitre.org/techniques/T1546/003/) Event Triggered Execution: Windows Management Instrumentation Event Subscription |
| Data needed | Sysmon 19-21 (WmiEvent), or Defender for Endpoint |
| Severity | High |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

A permanent WMI subscription runs a command or script whenever its filter fires (a timer, a logon, an uptime threshold), with no file in a Run key or task folder. It goes live when the filter is bound to the consumer (Sysmon 21). Only `CommandLineEventConsumer` and `ActiveScriptEventConsumer` can run code; the event log, log file and SMTP consumers can't and are not matched. Matching the binding gives one alert per install.

## Splunk

```spl
index=<windows_index> source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=21
    Operation IN ("Created", "Modified")
    (Consumer="*CommandLineEventConsumer*" OR Consumer="*ActiveScriptEventConsumer*")
| stats count min(_time) as first_seen values(Filter) as filter values(Consumer) as consumer by host, User
| convert ctime(first_seen)
```

## Microsoft Sentinel

Defender for Endpoint records the binding as `WmiBindEventFilterToConsumer`. The consumer details sit in `AdditionalFields`; check their exact layout in your tenant.

```kql
DeviceEvents
| where TimeGenerated > ago(1h)
| where ActionType == "WmiBindEventFilterToConsumer"
| where AdditionalFields has_any ("CommandLineEventConsumer", "ActiveScriptEventConsumer")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, AdditionalFields
```

## Elastic

```eql
any where event.code == "21" and
  winlog.event_data.Operation : ("Created", "Modified") and
  winlog.event_data.Consumer : ("*CommandLineEventConsumer*", "*ActiveScriptEventConsumer*")
```

## False positives

- Management, monitoring or vendor agents that register their own command-line or script consumers.
- Administrators using WMI subscriptions for scheduled maintenance.

Allowlist by exact consumer name and command.

## Blind spots

- Hosts without Sysmon WmiEvent logging. WMI-Activity/Operational 5861 also records permanent subscriptions and is the fallback.
- Custom or third-party consumer classes that run code.
- Temporary (in-process) subscriptions, which end with the process and aren't persistence.

## Validate

In a lab VM, as administrator. The consumer starts Notepad when the system has been up for over 4 minutes:

```powershell
$f = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
  Name = "LabFilter"; EventNamespace = "root\cimv2"; QueryLanguage = "WQL"
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240" }
$c = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
  Name = "LabConsumer"; CommandLineTemplate = "notepad.exe" }
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{ Filter = $f; Consumer = $c }
```

Clean up by removing the three objects (`Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject`, and the same for `__EventFilter` and `CommandLineEventConsumer` named `Lab*`).

## Respond

Read the consumer's command (Sysmon 20 with the same name, `Destination`) and the filter's query (Sysmon 19). For a malicious subscription, remove the binding, consumer and filter from `root\subscription`, handle the payload it ran, and search other hosts for the same consumer name.
