## bulk download from S3 (e.g. cloudtrail)

```bash
aws s3 sync s3://bucketname/AWSLogs/ /target-folder
```

## describe cloudtrail
```bash
aws cloudtrail describe-trails
```