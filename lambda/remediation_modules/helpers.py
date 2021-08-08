#import boto3
from remediation_modules.logger import get_logs, log
from botocore.exceptions import ClientError

global_cidr_list = [ '0.0.0.0/0', '::/0' ]
all_protocols_id = "-1"

def authorize_subset_sg(sg_id, ip_perm, ec2, dryRun):
    cidr_ipv4 = []
    cidr_ipv6 = []

    try:
        for ip_range in ip_perm['IpRanges']:
            log("Ip_range (v4) is : " + ip_range['CidrIp'] )
            if (ip_range['CidrIp'] not in global_cidr_list):
                cidr_ipv4.append({'CidrIp': ip_range['CidrIp']})
            
        for ip_range in ip_perm['Ipv6Ranges']:
            log("Ip_range (v6) is : " + ip_range['CidrIpv6'] )
            if (ip_range['CidrIpv6'] not in global_cidr_list):
                cidr_ipv6.append({'CidrIpv6': ip_range['CidrIpv6']}
                    )
    except KeyError:
        return
    
    if cidr_ipv4 or cidr_ipv6:
            subset_ip_perm = dict(ip_perm)
            subset_ip_perm['IpRanges'] = cidr_ipv4
            subset_ip_perm['Ipv6Ranges'] = cidr_ipv6

            try:
                log("Executing authorize_security_group_ingress for " + str(subset_ip_perm))
                ec2.authorize_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions = [subset_ip_perm],
                    DryRun=dryRun
                    )
            except ClientError as e:
                print(e.response['Error']['Message'])
                log(e.response['Error']['Message'], "ERROR")

def cut_non_global_range_ip_perm(ip_perm):
    try:
        for index, ip_range in enumerate(ip_perm['IpRanges']):
            if (ip_range['CidrIp'] not in global_cidr_list):
                log("Ignoring non-global IP, ip_range (v4) is : " + ip_range['CidrIp'])
                del ip_perm['IpRanges'][index]
            
        for index, ip_range in enumerate(ip_perm['Ipv6Ranges']):
            if (ip_range['CidrIpv6'] not in global_cidr_list):
                log("Ignoring non-global IP, ip_range (v6) is : " + ip_range['CidrIpv6'])
                del ip_perm['Ipv6Ranges'][index]
    except KeyError as e:
        log(e.response['Error']['Message'], "ERROR")
    
def handle_sg_perms_single_mode(sg_id, ip_perm, port_to_remove, ec2, dryRun):
    # get the current permission's relevant information
    try:
        from_port   = int(ip_perm['FromPort'])
    except KeyError:
        if ip_perm['IpProtocol'] == all_protocols_id:
            log("Receieved ingress rule with IP permission:  " + str(ip_perm))
            log("We cannot remove specific port or port ranges when all ports and all protocols are exposed to the public, please use the 'All Ports' parameter to resolve such cases", "ERROR")
            return
        else:
            return
    else:
        to_port     = int(ip_perm['ToPort'])
        ip_protocol = ip_perm['IpProtocol']

    # check if the current port is contained in the permission
    if(from_port <= port_to_remove <= to_port):
        try:
            log("Executing revoke_security_group_ingress for " + str(ip_perm))
            ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions = [ip_perm],
                DryRun=dryRun
            )
        except ClientError as e:
            log(e.response['Error']['Message'], "ERROR")
        
        if(from_port == port_to_remove == to_port):
            log("Port is perfectly contained (remove this ip permission)")
        else:
            log("Port is partially contained (remove the rule and create two subset rule)")

            ip_perms_split_start = dict(ip_perm)
            ip_perms_split_end = dict(ip_perm)

            ip_perms_split_start['ToPort'] = int(port_to_remove) - 1
            ip_perms_split_end['FromPort'] = int(port_to_remove) + 1
            
            # check if the from port and to port are valid for a new rule
            if(ip_perms_split_start['FromPort'] <= ip_perms_split_start['ToPort']):
                try:
                        log("Executing authorize_security_group_ingress for " + str(ip_perms_split_start))
                        ec2.authorize_security_group_ingress(
                            GroupId=sg_id,
                            IpPermissions = [ip_perms_split_start],
                            DryRun=dryRun
                        )
                except ClientError as e:
                    log(e.response['Error']['Message'], "ERROR")
            
            # check if the from port and to port are valid for a new rule
            if(ip_perms_split_end['FromPort'] <= ip_perms_split_end['ToPort']):
                try:
                    
                        log("Executing authorize_security_group_ingress for " + str(ip_perms_split_end))
                        ec2.authorize_security_group_ingress(
                            GroupId=sg_id,
                            IpPermissions = [ip_perms_split_end],
                            DryRun=dryRun
                        )
                except ClientError as e:
                    log(e.response['Error']['Message'], "ERROR")

def handle_sg_perms_range_mode(sg_id, ip_perm, port_range, ec2, dryRun):
    # get the current permission's relevant information
    try:
        from_port   = int(ip_perm['FromPort'])
    except KeyError:
        if ip_perm['IpProtocol'] == all_protocols_id:
            log("Receieved ingress rule with IP permission: " + str(ip_perm))
            log("We cannot remove specific port or port ranges when all ports and all protocols are exposed to the public, please use the 'All Ports' parameter to resolve such cases", "ERROR")
            return
        else:
            return
    else:
        to_port     = int(ip_perm['ToPort'])
        ip_protocol = ip_perm['IpProtocol']

    # if the from and to port are the same, this needs to be handled by single mode, and will be done later
    # if needed by the parent module
    if(from_port == to_port):
        return

    if(from_port >= port_range[0] and from_port <= port_range[1]):
        # the from_port is contained in the port range
        
        # check if the to_port is also contained in the port range
        if(to_port >= port_range[0] and to_port <= port_range[1]):
            # both ports are contained in the port range, which
            # means we just need to revoke this permission
            log("Ports are perfectly contained (remove this ip permission)")
            
            try:
                log("Executing revoke_security_group_ingress for " + str(ip_perm))
                ec2.revoke_security_group_ingress(
                                GroupId=sg_id,
                                IpPermissions = [ip_perm],
                                DryRun=dryRun
                            )
            except ClientError as e:
                log(e.response['Error']['Message'], "ERROR")
            return
        
        elif(to_port >= port_range[1]):
            # from_port is contained in the range, and to_port is out of range in the high range
            # which means we need to create the permissions from the higher range of this rule
            log("Ports are partially contained in a margin right (remove one rule and create one subset rule)")
            subset_ip_perm = dict(ip_perm)
            subset_ip_perm['FromPort'] = port_range[1] + 1

            try:
                log("Executing revoke_security_group_ingress for " + str(ip_perm))
                ec2.revoke_security_group_ingress(
                                GroupId=sg_id,
                                IpPermissions = [ip_perm],
                                DryRun=dryRun
                            )
            except ClientError as e:
                log(e.response['Error']['Message'], "ERROR")
            
            try:
                log("Executing authorize_security_group_ingress for " + str(subset_ip_perm))
                ec2.authorize_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions = [subset_ip_perm],
                    DryRun=dryRun
                    )
            except ClientError as e:
                log(e.response['Error']['Message'], "ERROR")
            
            return
    if(to_port >= port_range[0] and to_port <= port_range[1]):
        # to_port is contained in the port range
        
        if(from_port >= port_range[0] and from_port <= port_range[1]):
            # to_port is contained in the port range and from_port is contained in the port range
            # which means we need to remove this rule 
            # this should have been handled before
            log("Ports are perfectly contained (remove this ip permission)")
            
            try:
                log("Executing revoke_security_group_ingress for " + str(ip_perm))
                ec2.revoke_security_group_ingress(
                                GroupId=sg_id,
                                IpPermissions = [ip_perm],
                                DryRun=dryRun
                            )
            except ClientError as e:
                log(e.response['Error']['Message'], "ERROR")
        
        elif(from_port <= port_range[0]):
            # to_port is contained in the port range , and from_port is out of range in the lower range
            # so we need to remove the higher end of the port range and create the lower end
            log("Ports are partially contained in a margin left (remove one rule and create one subset rule)")
            subset_ip_perm = dict(ip_perm)
            subset_ip_perm['ToPort'] = port_range[0] - 1
            
            try:
                log("Executing revoke_security_group_ingress for " + str(ip_perm))
                ec2.revoke_security_group_ingress(
                                GroupId=sg_id,
                                IpPermissions = [ip_perm],
                                DryRun=dryRun
                            )
            except ClientError as e:
                log(e.response['Error']['Message'], "ERROR")
            
            try:
                log("Executing authorize_security_group_ingress for " + str(subset_ip_perm))
                ec2.authorize_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions = [subset_ip_perm],
                    DryRun=dryRun
                    )
            except ClientError as e:
                log(e.response['Error']['Message'], "ERROR")
            return

    # check if the input ports are contained inside of this current
    # permission, if yes, should remove the relevant ports and create two
    # new rules, from the high end and from the low end of the port range
    if(from_port <= port_range[0] and to_port >= port_range[1]):
        log("Ports are contained from both sides (remove the rule and create two subset rule)")
        subset_ip_perm_left = dict(ip_perm)
        subset_ip_perm_left['ToPort'] = port_range[0] - 1

        subset_ip_perm_right = dict(ip_perm)
        subset_ip_perm_right['FromPort'] = port_range[1] + 1

        try:
            log("Executing revoke_security_group_ingress for " + str(ip_perm))
            ec2.revoke_security_group_ingress(
                            GroupId=sg_id,
                            IpPermissions = [ip_perm],
                            DryRun=dryRun
                        )
        except ClientError as e:
            log(e.response['Error']['Message'], "ERROR")
        
        try:
            log("Executing authorize_security_group_ingress for " + str(subset_ip_perm_left))
            ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions = [subset_ip_perm_left],
                DryRun=dryRun
                )
        except ClientError as e:
            log(e.response['Error']['Message'], "ERROR")
        
        try:
            log("Executing authorize_security_group_ingress for " + str(subset_ip_perm_right))
            ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions = [subset_ip_perm_right],
                DryRun=dryRun
                )
        except ClientError as e:
            log(e.response['Error']['Message'], "ERROR")
        
        return

def handle_sg_perms_all_mode(sg_id, ip_perm, ec2, dryRun):
    # get the current permission's relevant information
    try:
        ip_protocol = ip_perm['IpProtocol'] 
    except KeyError:
        return
    
    try:
        to_port     = int(ip_perm['ToPort'])
        from_port   = int(ip_perm['FromPort'])
    except KeyError:
        if(not ip_protocol == all_protocols_id):
            return
    else:
        # check if this permission covers all ports
        if(from_port == 0 and to_port == 65535):
            # if it does set the port range input to be from_port and to_port
            # and send to the range function to handle it
            port_range=[0,65535]
            handle_sg_perms_range_mode(sg_id, ip_perm, port_range, ec2, dryRun)
     

    # check if this ip_protocol is '-1' and remove it if so
    if ip_protocol == all_protocols_id:
        try:
            log("Executing revoke_security_group_ingress for " + str(ip_perm))
            ec2.revoke_security_group_ingress(
                            GroupId=sg_id,
                            IpPermissions = [ip_perm],
                            DryRun=dryRun
                        )
        except ClientError as e:
            log(e.response['Error']['Message'], "ERROR")
        
def revoke_all_rules(sg_id, ec2, dryRun):
    try:
        group = ec2.describe_security_groups(GroupIds=[ sg_id, ])['SecurityGroups']
    except ClientError as e:
        log(e.response['Error']['Message'], "ERROR")
        return
    
    egressRules = group[0]['IpPermissionsEgress']
    log("Egress rules to be deleted: " + str(egressRules))

    ingressRules = group[0]['IpPermissions']
    log("Ingress rules to be deleted: " + str(ingressRules))

    if ingressRules:
        for i, v in enumerate(ingressRules):
            try:
                del ingressRules[i]['UserIdGroupPairs'][0]['GroupName']
            except Exception as e: 
                continue
        try:
            log("Executing revoke_security_group_ingress for " + str(ingressRules))
            ec2.revoke_security_group_ingress(
                            GroupId=sg_id,
                            IpPermissions=ingressRules,
                            DryRun=dryRun
                        )
        except ClientError as e:
            log(e.response['Error']['Message'], "ERROR")
    
    if egressRules:
        for i, v in enumerate(egressRules):
            try:
                del egressRules[i]['UserIdGroupPairs'][0]['GroupName']
            except Exception as e: 
                continue
        try:
            log("Executing revoke_security_group_ingress for " + str(egressRules))
            ec2.revoke_security_group_egress(
                            GroupId=sg_id,
                            IpPermissions=egressRules,
                            DryRun=dryRun
                        )
        except ClientError as e:
            log(e.response['Error']['Message'], "ERROR")
