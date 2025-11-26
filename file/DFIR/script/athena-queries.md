# Athena Queries
These are athena (or any other sql) queries to use on IR.
Of course this might be a bit different on how you use glue for the athena tables.

## Athena queries related to CloudTrail

### filter based on accesskeyid, username

AKIA is long lived access key which introduced more risk compared to ASIA.

```
SELECT * FROM "cloudtrail-table" 
where useridentity.accesskeyid like '%AKIASTUFFHERE%' 
limit 10;
```

```
SELECT * FROM "cloudtrail-table" 
where useridentity.username like '%AKIASTUFFHERE%' 
limit 10;

```

### check for attaching user policy eventname

```
SELECT * FROM "cloudtrail-table" 
where useridentity.accesskeyid like '%AKIASTUFFHERE%' 
and eventname='AttachUserPolicy' 
limit 10;
```

### check creation of accesskey

```
SELECT * FROM "cloudtrail-table" 
where useridentity.accesskeyid like '%AKIASTUFFHERE%' 
and eventname='CreateAccessKey' 
limit 10;
```

```
SELECT * FROM "cloudtrail-table" WHERE json_extract_scalar(responseelements, '$.accessKey.accessKeyId') IS NOT NULL;
```

### S3 activities with requestParameters filter

eventname related to S3 that you can play with: CreateBucket, DeleteBucket, PutBucketPolicy. Also some are data events, which are not on by default (PutObject, GetObject, DeleteObject, ListObject)


```
SELECT eventtime, eventname, useridentity, sourceipaddress, useragent, requestparameters, responseelements FROM "cloudtrail-table" where eventname = 'CreateBucket' and requestparameters like '%we-stole-ur-data-%'
```


## References
https://catalog.us-east-1.prod.workshops.aws/workshops/6a8ad836-10a6-4694-9a3b-f53f193041de/en-US/detection/cloudtrail-1