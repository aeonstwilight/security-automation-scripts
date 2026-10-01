# CloudTrail, GuardDuty, Config or flow logs disabled

| | |
|---|---|
| ID | AWS-001 |
| ATT&CK | [T1562.008](https://attack.mitre.org/techniques/T1562/008/) Impair Defenses: Disable or Modify Cloud Logs |
| Data needed | CloudTrail management events, all accounts and regions (`sourcetype=aws:cloudtrail` or the `AWSCloudTrail` table) |
| Severity | High |
| Status | Experimental. Logic reviewed; not yet validated against production data. |

## Why

Turning off the trail is one of the first things an attacker with enough privilege does, and it is rare in normal operations. Also evidence for NIST 800-53 AU-9.

## Splunk

```spl
index=<aws_index> sourcetype=aws:cloudtrail NOT errorCode=*
    ( (eventSource=cloudtrail.amazonaws.com eventName IN (StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors))
   OR (eventSource=guardduty.amazonaws.com eventName IN (DeleteDetector, UpdateDetector))
   OR (eventSource=config.amazonaws.com eventName IN (StopConfigurationRecorder, DeleteConfigurationRecorder, DeleteDeliveryChannel))
   OR (eventSource=ec2.amazonaws.com eventName=DeleteFlowLogs) )
| stats count min(_time) as first_seen max(_time) as last_seen values(eventName) as actions values(sourceIPAddress) as src_ip
    by userIdentity.arn, recipientAccountId, awsRegion
| convert ctime(first_seen) ctime(last_seen)
```

## Microsoft Sentinel

```kql
AWSCloudTrail
| where TimeGenerated > ago(1h)
| where isempty(ErrorCode)
| where (EventSource == "cloudtrail.amazonaws.com" and EventName in ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"))
     or (EventSource == "guardduty.amazonaws.com" and EventName in ("DeleteDetector", "UpdateDetector"))
     or (EventSource == "config.amazonaws.com" and EventName in ("StopConfigurationRecorder", "DeleteConfigurationRecorder", "DeleteDeliveryChannel"))
     or (EventSource == "ec2.amazonaws.com" and EventName == "DeleteFlowLogs")
| project TimeGenerated, RecipientAccountId, AWSRegion, UserIdentityArn, EventName, SourceIpAddress, UserAgent
```

## False positives

Infrastructure-as-code pipelines call `UpdateTrail` and `PutEventSelectors` on deploy. Allowlist the pipeline role; keep the event names.

## Validate

In a sandbox account, against a test trail:

```bash
aws cloudtrail stop-logging --name <test-trail>
aws cloudtrail start-logging --name <test-trail>
```

## Respond

Re-enable logging first, then review what the principal did in the gap using any organization trail or another region's records.
