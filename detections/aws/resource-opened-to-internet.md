# Security group opened to the internet or S3 public access block removed

| | |
|---|---|
| ID | AWS-005 |
| ATT&CK | [T1562.007](https://attack.mitre.org/techniques/T1562/007/) Impair Defenses: Disable or Modify Cloud Firewall |
| Data needed | CloudTrail management events, all accounts and regions (`sourcetype=aws:cloudtrail` or the `AWSCloudTrail` table) |
| Severity | Medium |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Exposure is created in one API call and often not noticed until it is found from outside. Evidence for NIST 800-53 SC-7.

## Splunk

```spl
index=<aws_index> sourcetype=aws:cloudtrail NOT errorCode=*
    ( (eventName=AuthorizeSecurityGroupIngress ("0.0.0.0/0" OR "::/0"))
   OR eventName IN (DeleteBucketPublicAccessBlock, DeleteAccountPublicAccessBlock) )
| table _time, recipientAccountId, awsRegion, userIdentity.arn, eventName, requestParameters.groupId, requestParameters.bucketName, sourceIPAddress
```

## False positives

A rule open to the world on 443 for a public load balancer is expected. Split the alert by port once it is stable, and raise severity for 22, 3389 and database ports.

## Validate

In a sandbox account, add and then remove an ingress rule for `0.0.0.0/0` on a test security group.

## Respond

Revert the change if unintended, then check flow logs or access logs for connections during the exposure window.
