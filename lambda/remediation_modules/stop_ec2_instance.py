from remediation_modules.logger import get_logs, log
from botocore.exceptions import ClientError

def remediate_action(session, event):
    # get the remediation configuration from the event
    try:
        dryRun = event['dryRun']
        instance = event['awsEntity']
    except Exception as e:
        log(e, "ERROR")
        return get_logs()
    
    # create the session client for the specific region
    ec2 = session.client('ec2', region_name = instance['region'])

    instance_ids=[]
    instance_ids += [instance['entity']['instanceId']]

    try:
        log("Executing stop_instances for " + str(instance_ids))
        ec2.stop_instances(InstanceIds=instance_ids, DryRun=dryRun)
    except ClientError as e:
        log(e.response['Error']['Message'], "ERROR")
        
    return get_logs()