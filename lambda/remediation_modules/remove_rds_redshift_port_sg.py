#import boto3
from remediation_modules.logger import get_logs, log
from botocore.exceptions import ClientError
from remediation_modules.helpers import handle_sg_perms_single_mode, cut_non_global_range_ip_perm

def remediate_action(session ,event):
    # get the remediation configuration from the event
    try:
        event_extra_parameters = event['extraParams']
        port_to_remove = event_extra_parameters['port']
        security_group_type = event_extra_parameters['sgType'] # can be EC2 or DB
        security_group = event['awsEntity']
        dryRun = event['dryRun']
    except Exception as e:
        log(e, "ERROR")
        return get_logs()
    
    if(security_group_type.upper() == 'EC2'):
        # get the security group ID
        sg_id = security_group['entity']['groupId']
        
        # create the session client for the specific region
        ec2 = session.client('ec2', region_name = security_group['region'])

        try:
            group = ec2.describe_security_groups(GroupIds=[ sg_id, ])['SecurityGroups']
        except ClientError as e:
            log(e.response['Error']['Message'], "ERROR")
            return get_logs()

        try:
            ip_perms = group[0]['IpPermissions']
        except (IndexError, KeyError):
            log('IP permissions not found for security group {}.'.format(sg_id), "ERROR")
            return get_logs()
        
        # move over all of the permissions to remove the port requested
        for ip_perm in ip_perms:
            # remove non global ip's from the permission
            # to avoid revoking relevant traffic
            cut_non_global_range_ip_perm(ip_perm)

            # remove the port
            handle_sg_perms_single_mode(sg_id, ip_perm, int(port_to_remove), ec2, dryRun)

    elif(security_group_type.upper() == 'DB'):
        # create the session client for the specific region
        rds = session.client('rds', region_name = security_group['region'])
        
        # get the security group ID
        db_sg_name = security_group['entity']['dbSecurityGroupName']

        try:
            db_sg = rds.describe_db_security_groups(DBSecurityGroupName=db_sg_name)['DBSecurityGroups'][0]
        except ClientError as e:
            log(e.response['Error']['Message'], "ERROR")
            return get_logs()

        for ip_range in db_sg['IPRanges']:
            if(ip_range['cidrip'] == '0.0.0.0/0'):
                if not dryRun:
                    log("Executing revoke_db_security_group_ingress for " + db_sg_name)
                    try:
                        rds.revoke_db_security_group_ingress(
                            DBSecurityGroupName=db_sg_name,
                            CIDRIP=ip_range['cidrip']
                            )
                    except ClientError as e:
                        log(e.response['Error']['Message'], "ERROR")
                else:
                    log("DryRun, did not actually revoke_db_security_group_ingress for " + db_sg_name)         
    else:
        log('security group type ' + security_group_type + ' not valid', "ERROR")

    return get_logs()