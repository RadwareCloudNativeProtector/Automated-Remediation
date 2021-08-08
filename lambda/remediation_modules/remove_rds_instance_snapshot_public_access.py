from remediation_modules.logger import get_logs, log
from botocore.exceptions import ClientError

def remediate_action(session, event):
    # get the remediation configuration from the event
    try:
        dryRun = event['dryRun']
        rds_entity = event['awsEntity']
        rds_id = rds_entity['entity']['dbSnapshotIdentifier']
    except Exception as e:
        log(e, "ERROR")
        return get_logs()

    # create the session client for the specific region
    rds = session.client('rds', region_name = rds_entity['region'])
    
    try:
        if not dryRun:
            log("Executing modify_db_snapshot_attribute for RDS with ID " + rds_id)
            rds.modify_db_snapshot_attribute( 
                DBSnapshotIdentifier = rds_id,  
                AttributeName = 'restore', 
                ValuesToRemove = [ 'all' ] )
        else:
            log("DryRun, did not actually remove rds snapshot public access from RDS with ID " + rds_id)
    except ClientError as e:
        log(e.response['Error']['Message'], "ERROR")
    
    return get_logs()