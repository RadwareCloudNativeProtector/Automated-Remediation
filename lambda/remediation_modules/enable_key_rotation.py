from remediation_modules.logger import get_logs, log
from botocore.exceptions import ClientError

def remediate_action(session, event):
    # get the remediation configuration from the event
    try:
        dryRun = event['dryRun']
        key=event['awsEntity']
        key_id = key['entity']['keyId']
    except Exception as e:
        log(e, "ERROR")
        return get_logs()

    try:
        # create an kms client session with the specific region
        kms = session.client('kms', region_name = key['region'])

        if not dryRun:
            log("Executing enable_key_rotation for key with id: " + key_id)
            kms.enable_key_rotation(KeyId=key_id)
        else:
            log("DryRun, did not actually enable key rotation to key with id: " + key_id)
    except ClientError as e:
        log(e.response['Error']['Message'], "ERROR")
        
    return get_logs()