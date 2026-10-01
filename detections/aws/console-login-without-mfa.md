# IAM user console login without MFA

| | |
|---|---|
| ID | AWS-003 |
| ATT&CK | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Valid Accounts: Cloud Accounts |
| Data needed | CloudTrail management events, all accounts and regions (`sourcetype=aws:cloudtrail` or the `AWSCloudTrail` table) |
| Severity | Medium |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

A password-only console login is the easiest cloud foothold. Evidence for NIST 800-53 IA-2(1).

## Splunk

```spl
index=<aws_index> sourcetype=aws:cloudtrail eventName=ConsoleLogin userIdentity.type=IAMUser
    "responseElements.ConsoleLogin"=Success "additionalEventData.MFAUsed"=No
| stats count min(_time) as first_seen values(sourceIPAddress) as src_ip
    by userIdentity.arn, recipientAccountId
| convert ctime(first_seen)
```

## False positives

None expected once the filter is right. The restriction to `IAMUser` matters: federated and IAM Identity Center sign-ins report `MFAUsed=No` because MFA happened at the identity provider. Verify MFA for those users in the identity provider's logs.

## Validate

Create an IAM user with a console password and no MFA device in a sandbox account, and sign in.

## Respond

Enforce MFA on the user, and review the session for anything beyond a normal login.
