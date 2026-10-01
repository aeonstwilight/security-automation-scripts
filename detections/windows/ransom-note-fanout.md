# Same file created in many folders

| | |
|---|---|
| ID | WIN-003 |
| ATT&CK | [T1486](https://attack.mitre.org/techniques/T1486/) Data Encrypted for Impact |
| Data needed | File creation events (Sysmon 11 or EDR) mapped to CIM Endpoint.Filesystem |
| Severity | High |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Ransomware usually drops a ransom note in every directory it touches. One file name appearing in dozens of folders on a host within minutes is unusual, and it still fires when files are encrypted in place.

## Splunk

```spl
| tstats summariesonly=true dc(Filesystem.file_path) as folders count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action=created Filesystem.file_name IN ("*.txt", "*.hta", "*.html", "*.url")
    by Filesystem.dest, Filesystem.file_name, _time span=5m
| `drop_dm_object_name(Filesystem)`
| where folders >= 20
```

## False positives

Software installers and source control checkouts create many identically named files such as `README.txt` or `LICENSE.txt`. Keep an exclusion list for those names on build servers and developer workstations.

## Validate

```powershell
Get-ChildItem C:\lab\testdata -Recurse -Directory | ForEach-Object { Set-Content -Path (Join-Path $_.FullName "HOW_TO_RECOVER.txt") -Value "test" }
```

## Respond

Isolate the host and read the note: it usually identifies the family, which tells you what else to look for.
