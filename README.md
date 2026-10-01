# Detections and SOC scripts

Detection logic I maintain for Splunk, Microsoft Sentinel and Elastic, plus a few triage scripts. Each detection is one file: what it looks for and why, the query for each platform, expected false positives, blind spots, how to trigger it safely, and what to do when it fires.

Longer write-ups for several of these are at [rwilliams.dev](https://rwilliams.dev).

## Status

Every detection here is marked **Experimental**: the logic has been reviewed, but it has not been validated against production data in this form. Field names depend on how your data was onboarded. Run each query against your own data, and trigger it in a lab using the Validate section, before enabling it as an alert.

## Conventions

- `<windows_index>` and `<aws_index>` are placeholders for your own indexes.
- Splunk queries use the CIM data models (Endpoint, Authentication) where one fits, so they work across log sources mapped to CIM.
- Sentinel queries use `SecurityEvent`, the Defender for Endpoint `Device*` tables, and `AWSCloudTrail`.
- Thresholds are starting points. Set them from your own baseline.

## Windows and Active Directory

| ID | Detection | ATT&CK | Severity |
|----|-----------|--------|----------|
| WIN-001 | [Shadow copy deletion and recovery tampering](detections/windows/inhibit-system-recovery.md) | [T1490](https://attack.mitre.org/techniques/T1490/) Inhibit System Recovery | High |
| WIN-002 | [Mass file rename collapsing many file types into one](detections/windows/mass-file-rename.md) | [T1486](https://attack.mitre.org/techniques/T1486/) Data Encrypted for Impact | Critical |
| WIN-003 | [Same file created in many folders](detections/windows/ransom-note-fanout.md) | [T1486](https://attack.mitre.org/techniques/T1486/) Data Encrypted for Impact | High |
| WIN-004 | [Bulk Active Directory account deletion](detections/windows/ad-bulk-account-deletion.md) | [T1531](https://attack.mitre.org/techniques/T1531/) Account Access Removal | High |
| WIN-005 | [Account created and deleted within a day](detections/windows/ad-short-lived-account.md) | [T1136.002](https://attack.mitre.org/techniques/T1136/002/) Create Account: Domain Account, [T1070.009](https://attack.mitre.org/techniques/T1070/009/) Clear Persistence | Medium |
| WIN-006 | [One source accessing admin shares on many hosts](detections/windows/admin-share-fanout.md) | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) Remote Services: SMB/Windows Admin Shares | High |
| WIN-007 | [One account authenticating to many hosts](detections/windows/network-logon-fanout.md) | [T1021](https://attack.mitre.org/techniques/T1021/) Remote Services, [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts | Medium |
| WIN-008 | [Command shell spawned by the WMI provider host](detections/windows/wmi-spawned-shell.md) | [T1047](https://attack.mitre.org/techniques/T1047/) Windows Management Instrumentation | Medium |
| WIN-009 | [Office application spawning a shell or script host](detections/windows/office-spawned-shell.md) | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) User Execution: Malicious File, [T1059](https://attack.mitre.org/techniques/T1059/) Command and Scripting Interpreter | High |

## AWS

| ID | Detection | ATT&CK | Severity |
|----|-----------|--------|----------|
| AWS-001 | [CloudTrail, GuardDuty, Config or flow logs disabled](detections/aws/logging-disabled.md) | [T1562.008](https://attack.mitre.org/techniques/T1562/008/) Impair Defenses: Disable or Modify Cloud Logs | High |
| AWS-002 | [Root user activity](detections/aws/root-user-activity.md) | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Valid Accounts: Cloud Accounts | High |
| AWS-003 | [IAM user console login without MFA](detections/aws/console-login-without-mfa.md) | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Valid Accounts: Cloud Accounts | Medium |
| AWS-004 | [Access key or console password created for another user](detections/aws/credentials-created-for-another-user.md) | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) Account Manipulation: Additional Cloud Credentials | High |
| AWS-005 | [Security group opened to the internet or S3 public access block removed](detections/aws/resource-opened-to-internet.md) | [T1562.007](https://attack.mitre.org/techniques/T1562/007/) Impair Defenses: Disable or Modify Cloud Firewall | Medium |

## Linux

| ID | Detection | ATT&CK | Severity |
|----|-----------|--------|----------|
| LNX-001 | [Shell or downloader spawned by a web server process](detections/linux/web-server-spawned-shell.md) | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) Server Software Component: Web Shell | High |

## Scripts

| File | Purpose |
|------|---------|
| [scripts/windows-triage.ps1](scripts/windows-triage.ps1) | PowerShell snippets for host and Active Directory triage |

## History

This repository previously held three large Splunk searches that combined many signals into a single risk score. They were replaced with the focused detections above, which are easier to test, tune and reason about. The originals remain in the git history.
