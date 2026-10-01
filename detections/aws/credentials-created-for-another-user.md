# Access key or console password created for another user

| | |
|---|---|
| ID | AWS-004 |
| ATT&CK | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) Account Manipulation: Additional Cloud Credentials |
| Data needed | CloudTrail management events, all accounts and regions (`sourcetype=aws:cloudtrail` or the `AWSCloudTrail` table) |
| Severity | High |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Creating a credential for a different user is a standard way to keep access after the original foothold is closed. Evidence for NIST 800-53 AC-2.

## Splunk

```spl
index=<aws_index> sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com NOT errorCode=*
    eventName IN (CreateAccessKey, CreateLoginProfile, UpdateLoginProfile)
| rename requestParameters.userName as target_user, userIdentity.userName as actor_user
| where isnotnull(target_user) AND (isnull(actor_user) OR target_user!=actor_user)
| table _time, recipientAccountId, userIdentity.arn, eventName, target_user, sourceIPAddress, userAgent
```

## False positives

Provisioning automation running under an assumed role. A role session has no `userName` to compare, so it is always included. Allowlist those role ARNs explicitly.

## Validate

In a sandbox account: `aws iam create-access-key --user-name <another-test-user>`, then delete the key.

## Respond

Disable the new credential, then review what the creating principal did before and after.
