from remediation_modules.logger import get_logs, log
from botocore.exceptions import ClientError

def remediate_action(session, event):
    # get the remediation configuration from the event
    try:
        event_extra_parameters = event['extraParams']
        keys_to_disable = event_extra_parameters['keyIndex']
        dryRun = event['dryRun']
        user = event['awsEntity']
        user_name = user['entity']['userName']
    except Exception as e:
        log(e, "ERROR")
        return get_logs()

    # convert the all key indices in the list to int
    keys_to_disable = [int(i) for i in keys_to_disable]

    try: 
        # create an iam client session with the specific region
        iam = session.client('iam', region_name = user['region'])
        if not dryRun:
            log("Executing list_access_keys for " + user_name)
            all_access_keys = iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
            
            # iterate over all of the access keys and disable their correlated indices
            for index ,key_to_disable in enumerate(all_access_keys):
                if ((index + 1) in keys_to_disable):
                    # extract the current keyId to disable
                    keyId = key_to_disable['AccessKeyId']
                    log("Executing update_access_key for user " + user_name + " and key index " + str(index + 1))
                    try:
                        iam.update_access_key(
                        UserName=user_name,
                        AccessKeyId=keyId,
                        Status='Inactive'
                        )
                    except ClientError as e:
                        log(e.response['Error']['Message'], "ERROR")
                else:
                    log("No access key exists for " + user_name + " in key index " + str(index + 1))
        else:
            log("DryRun, did not actually disable access keys for " + user_name)
    
    except ClientError as e:
        log(e.response['Error']['Message'], "ERROR")
    
    return get_logs()