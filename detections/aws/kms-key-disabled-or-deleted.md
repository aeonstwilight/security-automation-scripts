# KMS key disabled, scheduled for deletion or key material deleted

| | |
|---|---|
| ID | AWS-007 |
| ATT&CK | [T1485](https://attack.mitre.org/techniques/T1485/) Data Destruction |
| Data needed | CloudTrail management events, all accounts and regions (`sourcetype=aws:cloudtrail` or the `AWSCloudTrail` table) |
| Severity | Medium |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Everything encrypted under a KMS key (S3 objects, EBS volumes and snapshots, RDS, secrets) is lost when the key goes. `ScheduleKeyDeletion` destroys it after 7 to 30 days, `DisableKey` stops it working until re-enabled, and `DeleteImportedKeyMaterial` makes a key with imported material unusable at once. An attacker with KMS rights can destroy data or hold it to ransom this way. Failed calls are included.

## Splunk

```spl
index=<aws_index> sourcetype=aws:cloudtrail eventSource=kms.amazonaws.com
    eventName IN (ScheduleKeyDeletion, DisableKey, DeleteImportedKeyMaterial)
| stats count min(_time) as first_seen values(eventName) as actions values(requestParameters.keyId) as key_id
    values(errorCode) as error values(sourceIPAddress) as src_ip
    by userIdentity.arn, recipientAccountId, awsRegion
| convert ctime(first_seen)
```

## Microsoft Sentinel

```kql
AWSCloudTrail
| where TimeGenerated > ago(1h)
| where EventSource == "kms.amazonaws.com"
| where EventName in ("ScheduleKeyDeletion", "DisableKey", "DeleteImportedKeyMaterial")
| extend KeyId = tostring(parse_json(RequestParameters).keyId)
| project TimeGenerated, RecipientAccountId, AWSRegion, UserIdentityArn, EventName, KeyId, ErrorCode, SourceIpAddress, UserAgent
```

## False positives

- Planned key retirement or clean-up of unused keys by their owners.
- Infrastructure-as-code destroying a stack that owns a key.

Allowlist by identity and key alias.

## Blind spots

- Locking the owner out with `PutKeyPolicy`, or re-encrypting data under an attacker-held key.
- Keys removed through other services without these calls.

## Validate

In a sandbox account, with a test key:

```bash
aws kms schedule-key-deletion --key-id <test-key-id> --pending-window-in-days 7
aws kms cancel-key-deletion --key-id <test-key-id>
```

## Respond

If there is any doubt, cancel the deletion (`CancelKeyDeletion`) or re-enable the key first, then investigate. Find out what the key protects and look for the rest of the destruction pattern from the same identity: deleted snapshots and objects, versioning or lifecycle changes, logging turned off, new access keys.
