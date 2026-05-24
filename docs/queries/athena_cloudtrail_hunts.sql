-- CloudTrail threat-hunting starter queries for a real deployment.
-- Replace table/partition names with your organization-specific Athena schema.

-- 1. AccessDenied bursts by principal
SELECT useridentity.arn AS principal, eventsource, eventname, count(*) AS denied_count
FROM cloudtrail_logs
WHERE errorcode IN ('AccessDenied', 'UnauthorizedOperation', 'Client.UnauthorizedOperation')
  AND eventtime > current_timestamp - interval '24' hour
GROUP BY useridentity.arn, eventsource, eventname
ORDER BY denied_count DESC;

-- 2. IAM privilege escalation and persistence actions
SELECT eventtime, useridentity.arn AS principal, eventname, sourceipaddress, useragent
FROM cloudtrail_logs
WHERE eventname IN ('CreateAccessKey', 'AttachUserPolicy', 'PutUserPolicy', 'PassRole', 'CreatePolicyVersion', 'SetDefaultPolicyVersion')
ORDER BY eventtime DESC;

-- 3. Root account usage
SELECT eventtime, eventname, sourceipaddress, useragent
FROM cloudtrail_logs
WHERE useridentity.type = 'Root'
ORDER BY eventtime DESC;
