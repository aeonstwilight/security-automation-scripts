# Root user activity

| | |
|---|---|
| ID | AWS-002 |
| ATT&CK | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Valid Accounts: Cloud Accounts |
| Data needed | CloudTrail management events, all accounts and regions (`sourcetype=aws:cloudtrail` or the `AWSCloudTrail` table) |
| Severity | High |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

The root user should be used for a handful of account-level tasks and nothing else. Evidence for NIST 800-53 AC-6.

## Splunk

```spl
index=<aws_index> sourcetype=aws:cloudtrail userIdentity.type=Root
    eventType!=AwsServiceEvent NOT userIdentity.invokedBy=*
| stats count min(_time) as first_seen values(eventName) as actions values(sourceIPAddress) as src_ip values(userAgent) as user_agent
    by recipientAccountId
| convert ctime(first_seen)
```

## Microsoft Sentinel

```kql
AWSCloudTrail
| where TimeGenerated > ago(1h)
| where UserIdentityType == "Root" and EventTypeName != "AwsServiceEvent" and isempty(UserIdentityInvokedBy)
| summarize Actions = make_set(EventName, 50), SourceIps = make_set(SourceIpAddress, 10), Count = count()
    by RecipientAccountId
```

## False positives

The two exclusions remove events AWS services generate on the account's behalf. What remains should be near zero.

## Validate

Sign in to a sandbox account as root and view any console page.

## Respond

Confirm with the account owner. If unexpected, rotate the root password, check MFA devices and review every action in the session.
