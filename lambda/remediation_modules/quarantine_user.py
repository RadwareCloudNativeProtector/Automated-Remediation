from remediation_modules.logger import get_logs, log
from botocore.exceptions import ClientError

available_actions = ['DeleteConsoleAccess', 'DisableAccessKeys']

def remediate_action(session, event):
    # get the remediation configuration from the event
    try:
        event_extra_parameters = event['extraParams']
        actions = event_extra_parameters['actions']
        dryRun = event['dryRun']
        user = event['awsEntity']
        user_name = user['entity']['userName']
    except Exception as e:
        log(e, "ERROR")
        return get_logs()

    # check which action should be done in this run
    do_disable_console_access = available_actions[0] in list(event_extra_parameters['actions'])
    do_disable_access_keys = available_actions[1] in list(event_extra_parameters['actions'])

    # create the session client for the specific region
    iam = session.client('iam', region_name = user['region'])
    
    # disable console access if requested
    if(do_disable_console_access):            
        if not dryRun:
            try: 
                log("Executing delete_login_profile for " + user_name)
                iam.delete_login_profile(
                    UserName=user_name
                )
            except ClientError as e:
                log(e.response['Error']['Message'], "ERROR")
        else:
            log("DryRun, did not actually disable console access to " + user_name)
    
    # disable all access keys if requested
    if(do_disable_access_keys):
        log("Executing list_access_keys for " + user_name)
        all_access_keys = iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']

        if not dryRun:
            for key_to_disable in all_access_keys:
                access_key_id = key_to_disable['AccessKeyId']
                try:
                    log("Executing update_access_key for " + access_key_id)
                    iam.update_access_key(
                        UserName=user_name,
                        AccessKeyId=access_key_id,
                        Status='Inactive'
                    )
                except ClientError as e:
                    log(e.response['Error']['Message'], "ERROR")
        else:
            log("DryRun, did not actually disable access keys for " + user_name)
    
    return get_logs()