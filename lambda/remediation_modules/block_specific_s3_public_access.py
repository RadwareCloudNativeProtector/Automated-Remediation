from remediation_modules.logger import get_logs, log
from botocore.exceptions import ClientError
import json
import copy

publicURIs = ['http://acs.amazonaws.com/groups/global/AllUsers', 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers']

acl_permissions = {
    'READ': [],
    'WRITE': ['WRITE', 'FULL_CONTROL'],
    'LIST': ['READ', 'FULL_CONTROL'],
    'MANAGE': ['READ_ACP', 'WRITE_ACP', 'FULL_CONTROL'],
}
policy_permissions = {
    'READ': ['s3:*','s3:Get*','s3:GetObject'],
    'WRITE': ['s3:*','s3:Put*','s3:PutObject'],
    'LIST': ['s3:*','s3:List*','s3:ListBucket'],
    'MANAGE': ['s3:*','s3:Put*','s3:PutBucketAcl'],
}

def remove_duplicate_list(x):
  return list(dict.fromkeys(x))

def remediate_action(session, event):
    # get the remediation configuration from the event
    try:
        event_extra_parameters = event['extraParams']
        permissions = event_extra_parameters['permissions']
        dryRun = event['dryRun']
        account = event['accountId']
        bucket = event['awsEntity']
        bucket_name = bucket['entity']['name']
    except Exception as e:
        log(e, "ERROR")
        return get_logs()

    current_acl_permissions = []
    current_policy_permissions = []

    # find out which permissions we should handle, and create an updated dictionary accordingly
    for perm in permissions:
        current_acl_permissions += acl_permissions[perm.upper()]
        current_policy_permissions += policy_permissions[perm.upper()]
    
    # remove duplicates from both permission arrays
    current_acl_permissions = remove_duplicate_list(current_acl_permissions)
    current_policy_permissions = remove_duplicate_list(current_policy_permissions)
    updateAcl = False
    updatePolicy = False
    
    # create an s3 sessions with the specific region of the bucket
    s3 = session.client('s3', region_name = bucket['region'])

    # handle bucket acl access
    try:
        if not dryRun:
            log("Executing get_bucket_acl for " + bucket_name)
            # get the current bucket acl
            bucket_acls= s3.get_bucket_acl(
                Bucket=bucket_name,
                ExpectedBucketOwner=account
            )

            # create a new ACL object and set it's owner
            new_bucket_acls = {
                'Grants': []
            }
            new_bucket_acls['Owner'] = bucket_acls['Owner']

            # check which acl should be removed, and leave them out of the new ACL object
            for acl in bucket_acls['Grants']:
                
                # check if this ACL is valid
                if('Grantee' in acl and 
                    'Permission' in acl):

                    # check if this ACL fits out permission list, and skip adding it to 
                    # the list if it does
                    if ('URI' in acl['Grantee'] and 
                            acl['Grantee']['URI'] in publicURIs and 
                            acl['Permission'] in current_acl_permissions):
                        log('Removing ACL permission ' + str(acl))
                        updateAcl = True
                        continue

                    # add the acl, it is not public according to our conditions
                    new_bucket_acls['Grants'].append(acl)
                else:
                    log('unexpected ACL format ' + str(acl), 'ERROR')
                    continue
            
            # update the bucket ACL only if there was a change
            if(updateAcl):
                log("Executing put_bucket_acl for " + bucket_name)
                s3.put_bucket_acl(
                    Bucket=bucket_name,
                    AccessControlPolicy=new_bucket_acls
                    )
            else:
                log("There is no need to update bucket acls for: " + bucket_name)
        else:
            log("DryRun, did not actually alter bucket acl permissions for " + bucket_name)
    except ClientError as e:
        log(e.response['Error']['Message'], "ERROR")
    
    # handle bucket policy access
    try:
        if not dryRun:
            try:
                # get the current bucket acl and convert to json object
                log("Executing get_bucket_policy for " + bucket_name)
                bucket_policy= s3.get_bucket_policy(
                    Bucket=bucket_name,
                    ExpectedBucketOwner=account
                )
                bucket_policy_json = json.loads(bucket_policy['Policy'])
            except ClientError as e:
                if(e.response['Error']['Code'] == 'NoSuchBucketPolicy'):
                    log(e.response['Error']['Message'])
                    return get_logs()
                else:
                    log(e.response['Error']['Message'], "ERROR")

            # check if the policy exists
            if 'Statement' in bucket_policy_json:
                # create a new policy object
                new_policy = dict(bucket_policy_json)
                new_policy['Statement'] = []
                
                # iterate over all of the statement to validate against our conditions
                for statment in bucket_policy_json['Statement']:
                    removeStatement = False
                    newStatement = copy.deepcopy(statment)

                    if('Action', 'Effect', 'Principal' in statment):
                        if isinstance(statment['Action'], list):
                            # check if this policy fits out permission list, and skip adding it to 
                            # the list if it does
                            if (statment['Effect'].upper() == 'ALLOW' and
                                    statment['Principal'] == '*'):
                                newStatement['Action'] = \
                                    [action for action in statment['Action'] if action not in current_policy_permissions]
                                updatePolicy = True
                            
                            if not newStatement['Action']:
                                log('Removing policy statement ' + str(statment))
                                removeStatement = True
                                updatePolicy = True
                            else:
                                log("Not removing statement, will still allow " + str(newStatement['Action']))
                        else:
                            if (statment['Action'] in current_policy_permissions and 
                                        statment['Effect'].upper() == 'ALLOW' and 
                                        statment['Principal'] == '*'):
                                    log('removing Policy statement ' + str(statment))
                                    removeStatement = True
                                    updatePolicy = True
                                    continue

                        # add the statement, it is not public according to our conditions
                        if(not removeStatement):
                            new_policy['Statement'].append(newStatement)
                    else:
                        log('Unexpected policy format ' + str(statement), 'ERROR')
                        continue
                
                # update the bucket policy only if there was a change
                if(updatePolicy):
                    if(not new_policy['Statement']):
                        log("Executing delete_bucket_policy for " + bucket_name)
                        s3.delete_bucket_policy(
                            Bucket=bucket_name
                            )
                    else:
                        log("Executing put_bucket_policy for " + bucket_name)
                        s3.put_bucket_policy(
                            Bucket=bucket_name,
                            Policy=json.dumps(new_policy)
                            )
                else:
                    log('There is no need to update bucket policy for ' + bucket_name)
            else:
                log('There is no bucket policy statements for ' + bucket_name)
        else:
            log("DryRun, did not actually alter bucket policy permissions for " + bucket_name)
    except ClientError as e:
        log(e.response['Error']['Message'], "ERROR")
    
    return get_logs()