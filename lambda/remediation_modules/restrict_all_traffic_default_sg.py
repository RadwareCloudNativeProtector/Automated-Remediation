#import boto3
from remediation_modules.logger import get_logs, log
from botocore.exceptions import ClientError
from remediation_modules.helpers import revoke_all_rules

def remediate_action(session ,event):
    # get the remediation configuration from the event
    try:
        security_group = event['awsEntity']
        dryRun = event['dryRun']
        sg_id = security_group['entity']['groupId']
        sg_name = security_group['entity']['groupName']
    except Exception as e:
        log(e, "ERROR")
        return get_logs()

    ec2 = session.client('ec2', region_name = security_group['region'])
    
    # check if the SG name is default thus, this is the default sg
    if sg_name.lower() == 'default':
        try:
            group = ec2.describe_security_groups(GroupIds=[ sg_id, ])['SecurityGroups']
        except ClientError as e:
            log(e.response['Error']['Message'], "ERROR")
            return get_logs()

        try:
            revoke_all_rules(sg_id, ec2, dryRun)
        except ClientError as e:
            log(e.response['Error']['Message'], "ERROR")
    else:
        log("Trying to revoke all rules from a non default security group with name " + sg_name, "ERROR")
    
    return get_logs()