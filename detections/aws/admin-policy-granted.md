# IAM administrator-level policy granted

| | |
|---|---|
| ID | AWS-006 |
| ATT&CK | [T1098.003](https://attack.mitre.org/techniques/T1098/003/) Account Manipulation: Additional Cloud Roles |
| Data needed | CloudTrail management events, all accounts and regions (`sourcetype=aws:cloudtrail` or the `AWSCloudTrail` table) |
| Severity | High |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Granting admin to a user, role or group is the usual privilege escalation step in AWS, and a common way to keep access. Three patterns:

- attaching the AWS managed `AdministratorAccess` or `IAMFullAccess` policy (`IAMFullAccess` can grant itself anything)
- an inline policy or new policy version whose document allows `"Action": "*"` or `"iam:*"`
- `SetDefaultPolicyVersion`, a known way to roll a policy back to a permissive version (the event doesn't show the content, so it's matched by name)

Failed calls are included: a denied admin grant still shows intent and which credentials were used.

## Splunk

```spl
index=<aws_index> sourcetype=aws:cloudtrail eventSource=iam.amazonaws.com
    eventName IN (AttachUserPolicy, AttachRolePolicy, AttachGroupPolicy,
                  PutUserPolicy, PutRolePolicy, PutGroupPolicy, CreatePolicyVersion, SetDefaultPolicyVersion)
| rename requestParameters.policyArn as policy_arn, requestParameters.policyDocument as policy_document
| where match(policy_arn, ":policy/(AdministratorAccess|IAMFullAccess)$")
     OR match(policy_document, "\"Action\"\s*:\s*\[?\s*\"(\*|iam:\*)\"")
     OR eventName="SetDefaultPolicyVersion"
| eval target = coalesce('requestParameters.userName', 'requestParameters.roleName', 'requestParameters.groupName', 'requestParameters.policyArn')
| table _time, recipientAccountId, userIdentity.arn, eventName, target, policy_arn, errorCode, sourceIPAddress, userAgent
```

## Microsoft Sentinel

```kql
AWSCloudTrail
| where TimeGenerated > ago(1h)
| where EventSource == "iam.amazonaws.com"
| extend rp = parse_json(RequestParameters)
| extend PolicyArn = tostring(rp.policyArn), PolicyDocument = tostring(rp.policyDocument)
| where (EventName in ("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy")
         and PolicyArn matches regex @":policy/(AdministratorAccess|IAMFullAccess)$")
     or (EventName in ("PutUserPolicy", "PutRolePolicy", "PutGroupPolicy", "CreatePolicyVersion")
         and PolicyDocument matches regex @"""Action""\s*:\s*\[?\s*""(\*|iam:\*)""")
     or EventName == "SetDefaultPolicyVersion"
| extend Target = coalesce(tostring(rp.userName), tostring(rp.roleName), tostring(rp.groupName), PolicyArn)
| project TimeGenerated, RecipientAccountId, UserIdentityArn, EventName, Target, PolicyArn, ErrorCode, SourceIpAddress, UserAgent
```

## False positives

- Cloud administrators granting admin through the console or infrastructure-as-code.
- Break-glass or bootstrap roles set up with `AdministratorAccess`.

Allowlist the platform team's pipeline role; keep the event names.

## Blind spots

- Admin rights spread across statements, with `*` not first in an Action list, or granted through `NotAction` with an Allow.
- Attaching a customer-managed policy by ARN (its name doesn't say what it grants).
- Other routes to admin: `AddUserToGroup` into an admin group, `UpdateAssumeRolePolicy` on an admin role, passing an admin role to a new resource.

## Validate

In a sandbox account:

```bash
aws iam attach-user-policy --user-name <test-user> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam detach-user-policy --user-name <test-user> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

## Respond

Check who granted what to whom; an identity granting admin to itself, or to a user it just created, is the classic chain. Unless it matches a change ticket, detach or revert the policy (restore the previous default version), review the caller's credentials and what the target did after the grant.
