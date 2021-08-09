from remediation_modules.logger import get_logs, log
from botocore.exceptions import ClientError

desired_password_policy = {
    "MinimumPasswordLength": 14, # or more
    'PasswordReusePrevention': 24, # or more
    'MaxPasswordAge': 90, # or less
    "RequireSymbols": True,
    "RequireNumbers": True,
    "RequireUppercaseCharacters": True,
    "RequireLowercaseCharacters": True,
    "AllowUsersToChangePassword": True, # only in case of enabling password policy
}

ExpectedErrorCode = 'NoSuchEntity'

def remediate_action(session, event):
    # get the remediation configuration from the event
    try:
        event_extra_parameters = event['extraParams']
        attributes = event_extra_parameters['attributes']
        password_policy = event['awsEntity']
        dryRun = event['dryRun']
    except Exception as e:
        log(e, "ERROR")
        return get_logs()
    
    no_current_policy = False
    policy_args = {}

    try:
        iam = session.client('iam')
        log("Executing get_account_password_policy")
        current_policy = iam.get_account_password_policy()['PasswordPolicy']
    except ClientError as e:
        if (e.response['Error']['Code'] == ExpectedErrorCode):
            no_current_policy = True
        else:
            log(e.response['Error']['Message'], "ERROR")
            return get_logs()
    try:
        if not dryRun:
            if no_current_policy:       
                # enable the password policy with relevant values only
                log("No password policy found, enabling password policy for the account with relevant values only")
                policy_args = {}
                ## handle all attributes that were passed as relevant
                for attribute in attributes:
                    policy_args[attribute] = desired_password_policy[attribute]
            else:
                log("Found password policy, updating relevant values only")

                if('ExpirePasswords' in current_policy):
                    del current_policy['ExpirePasswords']

                policy_args = dict(current_policy)

                ## handle all attributes that were passed as relevant
                for attribute in attributes:
                    policy_args[attribute] = desired_password_policy[attribute]
                
                # add special treatment for numbered arguments
                if('MinimumPasswordLength' in policy_args):
                    if('MinimumPasswordLength' in current_policy):
                        policy_args['MinimumPasswordLength'] = \
                            max(int(current_policy['MinimumPasswordLength']), 
                                int(desired_password_policy['MinimumPasswordLength']))
                    else:
                        log('No attribute named MinimumPasswordLength exists in current policy - setting as default value: ' + str(desired_password_policy['MinimumPasswordLength']))
                        policy_args['MinimumPasswordLength'] = int(desired_password_policy['MinimumPasswordLength'])
                
                if('PasswordReusePrevention' in policy_args):
                    if('PasswordReusePrevention' in current_policy):
                        policy_args['PasswordReusePrevention'] = \
                            max(int(current_policy['PasswordReusePrevention']), 
                                int(desired_password_policy['PasswordReusePrevention']))
                    else:
                        log('No attribute named PasswordReusePrevention exists in current policy - setting as default value: ' + str(desired_password_policy['PasswordReusePrevention']))
                        policy_args['PasswordReusePrevention'] = int(desired_password_policy['PasswordReusePrevention'])

                if('MaxPasswordAge' in policy_args):
                    if('MaxPasswordAge' in current_policy):
                        policy_args['MaxPasswordAge'] = \
                            min(int(current_policy['MaxPasswordAge']), 
                                int(desired_password_policy['MaxPasswordAge']))
                    else:
                        log('No attribute named MaxPasswordAge exists in current policy - setting as default value: ' + str(desired_password_policy['MaxPasswordAge']))
                        policy_args['MaxPasswordAge'] = int(desired_password_policy['MaxPasswordAge'])
            
            log("Executing update_account_password_policy")
            iam.update_account_password_policy(**policy_args)
        else:
            log("DryRun, did not actually update_account_password_policy")
    except ClientError as e:
        log(e.response['Error']['Message'], "ERROR")
    
    return get_logs()
