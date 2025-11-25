## Cloudtrail

### grep username

```grep -r userName | sort -u```

### ConsoleLogin==Failure

```bash
cat <cloudtrail.json> | jq -cr '.Records[]|select(.eventSource=="signin.amazonaws.com" and .eventName=="ConsoleLogin" and .responseElements.ConsoleLogin=="Failure")|[.eventTime,.sourceIPAddress,.errorMessage,.awsRegion,.userIdentity.userName, .additionalEventData.MFAUsed]|@csv'
```

### Root login (ConsoleLogin root)

```bash
cat <cloudtrail.json> | jq -cr '.Records[]|select(.eventName == "ConsoleLogin" and .userIdentity.type == "Root") | [.eventTime, .eventSource, .additionalEventData.MFAUsed, .sourceIPAddress, .userAgent] |@csv' | sort | uniq
```

### Defense evasion (StopLogging, DeleteTrail, UpdateTrail)

```bash
cat <cloudtrail.json> | jq -cr '.Records[]|select(.eventName == "StopLogging" or .eventName == "DeleteTrail" or .eventName == "UpdateTrail")|[.eventTime, .errorMessage, .userIdentity.arn, .sourceIPAddress, .eventName, .userAgent, .awsRegion]|@csv'
```

other ideas include: 
`DeleteDetector`, `DeleteMembers`, `DisassociateFromMasterAccount`, `DisassociateMembers`, `StopMonitoringMembers` from GuardDuty

### Unauthorized calls 

Filter for `AccessDenied`, `UnauthorizedOperation`

```bash
cat <cloudtrail.json> | jq -cr '.Records[]|select(.errorCode == "AccessDenied" or .errorCode == "UnauthorizedOperation")|[.eventName, .userIdentity.arn]|@csv' | sort | uniq -c | sort -nr
```

### Whoami (GetCallerIdentity)

```bash
cat <cloudtrail.json> | jq -cr '.Records[]| select(.eventName == "GetCallerIdentity") | [.userIdentity.arn, .sourceIPAddress, .userAgent] |@csv' | sort | uniq -c | sort -nr
```

### Access Creds (GetSecretValue)

```bash
cat <cloudtrail.json> | jq -cr '.Records[]| select(.eventName == "GetSecretValue")'
```

### RunInstances with xLarge

```bash
cat <cloudtrail.json> | jq -cr '.Records[]| select(.eventName == "RunInstances")|.requestParameters.instanceType'| grep -E '\d{2}xlarge' | sort | uniq -c | sort -nr
```

### S3 bruteforce

filtering for `GetBucketAcl`, `NoSuchBucket`, `AccessDenied`

```bash
cat <cloudtrail.json> | jq -cr '.Records[]| select((.errorCode == "AccessDenied" or .errorCode == "NoSuchBucket") and .eventName == "GetBucketAcl")|[.userIdentity.arn, .sourceIPAddress, .userAgent, .errorCode]|@csv'| sort | uniq -c | sort -nr 
```

### Sus user agent

kali, parrot, powershell

```bash
cat <cloudtrail.json> | jq -cr '.Records[] | select((.userAgent | contains("kali")) or (.userAgent | contains("parrot")) or (.userAgent | contains("PowerShell")))|[.userIdentity.arn, .userAgent]|@csv'| sort | uniq -c | sort -nr
```

- some of the suspicious user agents you will notice the string ‘command/*’ at the end

```bash
cat <cloudtrail.json> | jq -cr '.Records[] | select(.userAgent | contains("command"))|.userAgent'|grep -oE 'command/[^\d]+.*'| sort | uniq -c | sort -nr
```

### Persistence

filter for `CreateAccessKey` and IAMUser

```bash
cat <cloudtrail.json> | jq -cr '.Records[]| select(.eventName == "CreateAccessKey" and .userIdentity.type == "IAMUser")|[.sourceIPAddress, .userIdentity.arn, .responseElements.accessKey.createDate, .responseElements.accessKey.status, .responseElements.accessKey.accessKeyId, .errorCode, .errorMessage]|@csv'
```

### search for certain accessKeyId

search for certain accessKeyId in responseElements and in userIdentity. 
Maybe combine with .eventname = createUser or assumeRole etc. in response elements.

```bash
cat cloudtrail.json | jq '.Records[]|select(.responseElements.credentials.accessKeyId and (.responseElements.credentials.accessKeyId|contains("AKIAxxx")))|[.eventName]'
```

```bash
cat cloudtrail.json | jq '.Records[] | select(.userIdentity.accessKeyId and (.userIdentity.accessKeyId | contains("AKIAxxx")))'
```


### references

https://medium.com/@george.fekkas/quick-and-dirty-cloudtrail-threat-hunting-log-analysis-b64af10ef923
https://medium.com/@markohalloran99/analysing-cloudtrail-user-agents-for-aws-forensics-and-incident-response-94a8457fb3cc