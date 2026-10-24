# EBS snapshot, AMI or RDS snapshot shared outside the account

| | |
|---|---|
| ID | AWS-008 |
| ATT&CK | [T1537](https://attack.mitre.org/techniques/T1537/) Transfer Data to Cloud Account |
| Data needed | CloudTrail management events, all accounts and regions (`sourcetype=aws:cloudtrail` or the `AWSCloudTrail` table) |
| Severity | Medium |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Sharing a snapshot is one API call, and the receiving account can then copy the whole disk or database. A snapshot can't be shared with its own account, so any added permission means data leaving it: to another account ID, an organization or OU, or to everyone (`all`). Covers EBS snapshots (`ModifySnapshotAttribute`, `createVolumePermission`), AMIs (`ModifyImageAttribute`, `launchPermission`) and RDS DB and cluster snapshots (`valuesToAdd`). Removing permissions doesn't match. Failed calls do.

## Splunk

```spl
index=<aws_index> sourcetype=aws:cloudtrail
    ( (eventSource=ec2.amazonaws.com eventName IN (ModifySnapshotAttribute, ModifyImageAttribute))
   OR (eventSource=rds.amazonaws.com eventName IN (ModifyDBSnapshotAttribute, ModifyDBClusterSnapshotAttribute)) )
| eval shared_with = mvappend(
      'requestParameters.createVolumePermission.add.items{}.userId',
      'requestParameters.createVolumePermission.add.items{}.group',
      'requestParameters.launchPermission.add.items{}.userId',
      'requestParameters.launchPermission.add.items{}.group',
      'requestParameters.launchPermission.add.items{}.organizationArn',
      'requestParameters.launchPermission.add.items{}.organizationalUnitArn',
      'requestParameters.valuesToAdd{}')
| where isnotnull(shared_with)
| table _time, recipientAccountId, userIdentity.arn, eventName, shared_with, errorCode, sourceIPAddress, userAgent
```

## Microsoft Sentinel

```kql
AWSCloudTrail
| where TimeGenerated > ago(1h)
| where (EventSource == "ec2.amazonaws.com" and EventName in ("ModifySnapshotAttribute", "ModifyImageAttribute"))
     or (EventSource == "rds.amazonaws.com" and EventName in ("ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute"))
| extend rp = parse_json(RequestParameters)
| extend SharedWith = coalesce(rp["createVolumePermission"]["add"]["items"],
                               rp["launchPermission"]["add"]["items"],
                               rp["valuesToAdd"])
| where array_length(SharedWith) > 0
| project TimeGenerated, RecipientAccountId, UserIdentityArn, EventName, SharedWith, ErrorCode, SourceIpAddress, UserAgent
```

## False positives

- Sharing with the organization's own build, backup or disaster-recovery accounts, or with a vendor.
- Software vendors publishing public AMIs on purpose.

Allowlist by identity and target account ID.

## Blind spots

- Copying instead of sharing: `CopySnapshot` or `CopyImage` into another account, `CreateStoreImageTask` to S3, RDS `StartExportTask`.
- Turning off EC2 block public access for snapshots or AMIs (`DisableSnapshotBlockPublicAccess`, `DisableImageBlockPublicAccess`).
- Other shareable resources (Redshift, Backup vaults, S3 buckets).

## Validate

In a sandbox account, with a test snapshot and a second sandbox account ID:

```bash
aws ec2 modify-snapshot-attribute --snapshot-id <snap-id> --attribute createVolumePermission --operation-type add --user-ids <other-account-id>
aws ec2 modify-snapshot-attribute --snapshot-id <snap-id> --attribute createVolumePermission --operation-type remove --user-ids <other-account-id>
```

## Respond

Check who received it: `all` is the most urgent, since anyone can copy it now; an account ID outside the organization is next. Revoke the share at once if it isn't expected (assume a public share was copied), then check what the snapshot holds and what else the identity did, including `CreateSnapshot` just before and KMS key policy changes granting the other account decrypt rights.
