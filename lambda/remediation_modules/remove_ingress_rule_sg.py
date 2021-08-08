#import boto3
from remediation_modules.logger import get_logs, log
from botocore.exceptions import ClientError
from remediation_modules.helpers import handle_sg_perms_all_mode, handle_sg_perms_range_mode, handle_sg_perms_single_mode,cut_non_global_range_ip_perm

def remediate_action(session ,event):
    # get the remediation configuration from the even
    try:
        event_extra_parameters = event['extraParams']
        ports_to_remove = event_extra_parameters['ports']
        dryRun = event['dryRun']
        security_group = event['awsEntity']
        sg_id = security_group['entity']['groupId']
    except Exception as e:
        log(str(e), "ERROR")
        return get_logs()

    # create the session client for the specific region
    ec2 = session.client('ec2', region_name = security_group['region'])
    
    # move 'all' ports to the first index handle it first
    for i, port in enumerate(ports_to_remove):
        if port.lower() == 'all':
            try:
                ports_to_remove.remove(port)
                ports_to_remove.insert(0, port)
            except ValueError:
                pass

    ports_to_remove_updated = list(ports_to_remove)

    # iterate over all of the ports requested to be removed
    for port_to_remove in ports_to_remove:
        
        # get the updated security group permissions, it might have changed in the last iteration
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
        
        # set the mode for this iteration based on the port_to_remove parameter
        try:
            current_port = str(port_to_remove)
            if (current_port.isdigit()):
                mode = "single_port"
            elif (current_port.lower() == "all"):
                mode = "all"
            else:
                port_range = current_port.split("-", 1)
                if (port_range[0].isdigit() and port_range[1].isdigit()):
                    mode = "range"
                    port_range[0] = int(port_range[0])
                    port_range[1] = int(port_range[1])
                else:
                    log("Couldn't interpret port/ports value: " + port_to_remove, "ERROR")
                    continue
        except TypeError as e:
            log(e, "ERROR")

        log("Ports to remove: " + str(port_to_remove).lower() + " and mode is: " + mode)        
        
        # iterate over all of the permissions in the security group
        for ip_perm in ip_perms:
            print("currently working on")
            print("ip permission: " + str(ip_perm))
            
            # remove non global ip's from the permission
            # to avoid revoking relevant traffic
            cut_non_global_range_ip_perm(ip_perm)

            # run the relevant function to handle the current mode
            if(mode == 'all'):
                handle_sg_perms_all_mode(sg_id, ip_perm, ec2, dryRun)
            elif(mode == 'range'):
                handle_sg_perms_range_mode(sg_id, ip_perm, port_range, ec2, dryRun)
            elif(mode == 'single_port'):
                handle_sg_perms_single_mode(sg_id, ip_perm, int(port_to_remove), ec2, dryRun)
    
    return get_logs()