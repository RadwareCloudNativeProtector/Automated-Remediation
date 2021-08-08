from remediation_modules.logger import get_logs, log
from botocore.exceptions import ClientError

def remediate_action(session, event):
    # get the remediation configuration from the event
    try:
        dryRun = event['dryRun']
        account = event['accountId']
        bucket = event['awsEntity']
        bucket_name = bucket['entity']['name']
    except Exception as e:
        log(e, "ERROR")
        return get_logs()

    try: 
        # create an s3 client session with the specific region
        s3 = session.client('s3', region_name = bucket['region'])
        
        if not dryRun:
            # create a rule to enable bucket encryption
            log("Executing put_bucket_encryption for " + bucket_name)
            s3.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [
                            {
                                'ApplyServerSideEncryptionByDefault': {
                                    'SSEAlgorithm': 'AES256'
                                },
                                'BucketKeyEnabled': True
                            },
                        ]
                },
                ExpectedBucketOwner=account
            )
        else:
            log("DryRun, did not actually enable server side encryption to " + bucket_name)
    except ClientError as e:
        log(e.response['Error']['Message'], "ERROR")
    
    return get_logs()