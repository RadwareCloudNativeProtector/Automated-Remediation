from remediation_modules.logger import get_logs, log
from botocore.exceptions import ClientError

def remediate_action(session, event):
    # get the remediation configuration from the event
    try:
        dryRun = event['dryRun']
        rds_entity = event['awsEntity']
    except Exception as e:
        log(e, "ERROR")
        return get_logs()

    try:
        # create an rds client session with the specific region
        rds = session.client('rds', region_name = rds_entity['region'])
        rds_id = rds_entity['entity']['dbInstanceIdentifier']

        if not dryRun:
            log("Blocking public access to RDS instance " + rds_id)
            rds.modify_db_instance(
                DBInstanceIdentifier = rds_id, 
                PubliclyAccessible = False
            )
        else:
            log("DryRun, did not actually block public access to " + rds_id)
    except ClientError as e:
        log(e.response['Error']['Message'], "ERROR")
    
    return get_logs()