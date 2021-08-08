from remediation_modules.logger import get_logs, log
from botocore.exceptions import ClientError

def remediate_action(session, event):
    # get the remediation configuration from the event   
    try:
        dryRun = event['dryRun']
        rs_entity = event['awsEntity']
        rs_id = rs_entity['entity']['clusterIdentifier']
    except Exception as e:
        log(e, "ERROR")
        return get_logs()

    try:
        # create an redshift client session with the specific region
        client = session.client('redshift', region_name = rs_entity['region'])
        
        if not dryRun:
            log("Blocking public access to RedShift Cluster " + rs_id)
            client.modify_cluster(
                ClusterIdentifier = rs_id, 
                PubliclyAccessible = False
            )
        else:
            log("DryRun, did not actually block public access to " + rs_id)
    except ClientError as e:
        log(e.response['Error']['Message'], "ERROR")
    
    return get_logs()