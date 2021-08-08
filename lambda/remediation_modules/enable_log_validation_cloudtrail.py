from remediation_modules.logger import get_logs, log
from botocore.exceptions import ClientError

def remediate_action(session, event):
    # get the remediation configuration from the event
    try:
        dryRun = event['dryRun']
        account = event['accountId']
        trail = event['awsEntity']
        trail_arn = trail['entity']['trailARN']
    except Exception as e:
        log(e, "ERROR")
        return get_logs()

    try: 
        # create an cloudtrail client session with the specific region
        cloudtrail = session.client('cloudtrail', region_name = trail['region'])
        
        if not dryRun:
            log("Executing update_trail for " + trail_arn)
            cloudtrail.update_trail(
                Name=trail_arn,
                EnableLogFileValidation=True
            )
        else:
            log("DryRun, did not actually enable log file validation to " + trail_arn)
    except ClientError as e:
        log(e.response['Error']['Message'], "ERROR")
    
    return get_logs()