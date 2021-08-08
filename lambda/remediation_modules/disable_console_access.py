from remediation_modules.logger import get_logs, log
from botocore.exceptions import ClientError

def remediate_action(session, event):
    # get the remediation configuration from the event   
    try:
        dryRun = event['dryRun']
        user = event['awsEntity']
        user_name = user['entity']['userName']
    except Exception as e:
        log(e, "ERROR")
        return get_logs()

    try:
        # create an redshift client session with the specific region
        iam = session.client('iam', region_name = user['region'])
        log("Executing delete_login_profile for " + user_name)
        if not dryRun:
            iam.delete_login_profile(
                UserName=user_name
            )
        else:
            log("DryRun, did not actually disable console access to " + user_name)
    except ClientError as e:
        log(e.response['Error']['Message'], "ERROR")
    
    return get_logs()