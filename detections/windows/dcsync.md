# Directory secrets replicated by a non-machine account (DCSync)

| | |
|---|---|
| ID | WIN-010 |
| ATT&CK | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) OS Credential Dumping: DCSync |
| Data needed | Security 4662 on domain controllers ("Audit Directory Service Access", with a SACL on the domain object) |
| Severity | High |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

DCSync asks a domain controller to replicate password hashes, so whoever runs it gets every domain credential, `krbtgt` included, without touching a DC's disk. Domain controllers replicate with their own machine accounts; a user or service account using the secrets replication right is the attack pattern (Mimikatz `lsadump::dcsync`, Impacket `secretsdump`).

Only the two rights that return secrets are matched: DS-Replication-Get-Changes-All (`1131f6ad-…`) and DS-Replication-Get-Changes-In-Filtered-Set (`89e95b76-…`). Plain Get-Changes (`1131f6aa-…`) is left out: it returns no secrets, and some directory-sync tools use it on its own. That also gives one alert per DCSync.

## Splunk

```spl
index=<windows_index> EventCode=4662
    ("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" OR "89e95b76-444d-4c62-991a-0facbeda640c")
| eval subject_user = coalesce(SubjectUserName, Account_Name)
| where NOT like(subject_user, "%$")
| stats count min(_time) as first_seen values(SubjectLogonId) as logon_id by dest, subject_user
| convert ctime(first_seen)
```

## Microsoft Sentinel

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4662
| where Properties contains "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
     or Properties contains "89e95b76-444d-4c62-991a-0facbeda640c"
| where SubjectUserName !endswith "$"
| project TimeGenerated, Computer, SubjectDomainName, SubjectUserName, SubjectLogonId, Properties
```

## Elastic

```eql
any where event.code == "4662" and
  winlog.event_data.Properties : ("*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*", "*89e95b76-444d-4c62-991a-0facbeda640c*") and
  not winlog.event_data.SubjectUserName : "*$"
```

## False positives

- Microsoft Entra Connect password hash sync (`MSOL_…` account, on the Entra Connect server).
- Backup, migration or AD auditing tools that replicate with a service account.

Allowlist by account name and source host together, never by account alone.

## Blind spots

- DCSync with a computer account: every account ending in `$` is excluded, including a member server or attacker-created computer account granted replication rights. A DC allowlist closes this but is environment-specific.
- DCs without the audit subcategory or SACL produce no 4662. Network detection of DRSUAPI `DsGetNCChanges` from a non-DC address is the complementary view.
- Granting the rights beforehand (5136 on the domain object's security descriptor) needs its own detection.

## Validate

In a lab domain, from a member host, as a domain admin:

```text
mimikatz # lsadump::dcsync /domain:lab.local /user:krbtgt
```

or `secretsdump.py -just-dc-user krbtgt lab.local/admin@<dc>`.

## Respond

Find the 4624 for `SubjectLogonId` on the same DC to get the source address. Unless the account and host are a known sync tool, treat it as full domain credential compromise: reset `krbtgt` twice, the account used, and privileged accounts, and look for golden tickets and pass-the-hash logons afterwards.
