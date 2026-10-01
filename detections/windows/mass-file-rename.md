# Mass file rename collapsing many file types into one

| | |
|---|---|
| ID | WIN-002 |
| ATT&CK | [T1486](https://attack.mitre.org/techniques/T1486/) Data Encrypted for Impact |
| Data needed | Defender for Endpoint file events (`DeviceFileEvents`) |
| Severity | Critical |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Extension watchlists are stale on arrival, because many families generate a random extension per victim. The behavior is harder to hide: one process renames documents, spreadsheets and images, and they all come out with the same new extension.

## Microsoft Sentinel

```kql
let window = 5m;
let min_renames = 200;
DeviceFileEvents
| where TimeGenerated > ago(1h)
| where ActionType == "FileRenamed"
| extend NewExt = tolower(extract(@"\.([^.\\]+)$", 1, FileName)),
         OldExt = tolower(extract(@"\.([^.\\]+)$", 1, PreviousFileName))
| where isnotempty(NewExt) and NewExt != OldExt
| summarize Renames = count(),
            Folders = dcount(FolderPath),
            OldExts = dcount(OldExt),
            NewExts = dcount(NewExt),
            SampleNewExt = take_any(NewExt)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessId, bin(TimeGenerated, window)
| where Renames >= min_renames and Folders >= 10 and OldExts >= 3 and NewExts <= 2
```

## False positives

Bulk file converters, photo and media tools, some backup and sync agents. Exclude by signed process and path, not by name alone.

## Blind spots

- Families that encrypt in place and keep the original file name. See [WIN-003](ransom-note-fanout.md).
- Endpoint agents sample and cap high-volume file events, so the counts are a floor. Tune the thresholds on your own data.

## Validate

In a lab, generate a few hundred files of mixed types across a dozen folders and rename them all to one extension:

```powershell
Get-ChildItem C:\lab\testdata -Recurse -File | Rename-Item -NewName { $_.Name + ".locked" }
```

## Respond

This is an impact-stage alert. Isolate the host immediately and check file servers the account can reach.
