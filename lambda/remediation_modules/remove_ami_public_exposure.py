from remediation_modules.logger import get_logs, log
from botocore.exceptions import ClientError

def remediate_action(session, event):
    # get the remediation configuration from the event
    try:
        dryRun = event['dryRun']
        ami_entity = event['awsEntity']
        ami_id = ami_entity['entity']['imageId']
    except Exception as e:
        log(e, "ERROR")
        return get_logs()

    # create the session client for the specific region
    ec2 = session.client('ec2', region_name = ami_entity['region'])

    # remove AMI public exposure by modifying the LaunchPermission
    try:
        log("Removing public exposure of AMI " + ami_id)
        ec2.modify_image_attribute(
            ImageId=ami_id,
            LaunchPermission={ 'Remove': [{'Group': 'all'}] },
            DryRun=dryRun
        )
    except ClientError as e:
        log(e.response['Error']['Message'], "ERROR")
    
    return get_logs()