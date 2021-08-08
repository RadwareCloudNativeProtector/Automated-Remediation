import json
import os
from remediation_modules.logger import log, get_logs, reset_logs
import boto3
from botocore.exceptions import ClientError
from importlib import import_module

def get_credentials(account_id):
    """
    Using STS assume role to obtain the temporary credentials of another AWS account

    returns dict:
        'error'    : None if credentials is acquired successfully. Otherwise, it contains error message
    """

    # get the cross account role name
    cross_account_role_name = os.getenv('CROSS_ACCOUNT_ROLE_NAME', None)
    if cross_account_role_name == None:
        return {'error': 'Lambda env variable CROSS_ACCOUNT_ROLE_NAME not specified.', 'data': None}

    # try creating a sessions using STS assume role, return the credentials if it worked or and error 
    # if it did not work
    try:
        resp = boto3.client('sts').assume_role(
            RoleArn = 'arn:aws:iam::{0}:role/{1}'.format(account_id, cross_account_role_name),
            RoleSessionName = 'CNPRemediation'
            )

        return {'error': None, 'data': resp['Credentials']}
    except ClientError as e:
        error = 'Failed to assume role. Error code: {0}'.format(e.response['Error']['Code'])
        return {'error': error, 'data': None}

def lambda_handler(event, context):
    print(str(event))
    reset_logs()
    # handle the event if the only request is the list of actions
    if(event['actionId'] == "list_actions"):
        with open('remediation_actions.json') as json_file:
            actionList = json.load(json_file)

        # try to get the execution role, and set a default message for when we couldn't find 
        # the execution role from the function's context
        execution_role_arn = "couldn't find execution role arn"
        if context.invoked_function_arn:
            client = boto3.client('lambda')
            response = client.get_function(FunctionName=context.invoked_function_arn)
            execution_role_arn = str(response['Configuration']['Role'])
            
        log("Role arn is " + execution_role_arn)

        # get the role name from the environment variable
        cross_account_role_name = os.getenv('CROSS_ACCOUNT_ROLE_NAME', None)
        
        # raise an error if it's not specified
        if cross_account_role_name == None:
            log('Lambda env variable CROSS_ACCOUNT_ROLE_NAME not specified', "ERROR")
            return

        # add the role names and arn to the action list and return it
        actionList["primaryExecutionRoleArn"] = execution_role_arn
        actionList["remediationRoleName"] = cross_account_role_name
        return actionList
    else:
        # get the credentials for this account and create a session

        # get the account id from the context of lambda arn
        # result will be for example: self_account_id = '578458578721'
        
        self_account_id = context.invoked_function_arn.split(":")[4] 
        if event['accountId'] == self_account_id:
            session = boto3.Session()
            print("passed session stage: " + str(session))
        else:
            credentials = get_credentials(event['accountId'])
            if credentials['error'] is None:
                session = boto3.Session(
                    aws_access_key_id = credentials['data']['AccessKeyId'],
                    aws_secret_access_key = credentials['data']['SecretAccessKey'],
                    aws_session_token = credentials['data']['SessionToken']
                )
            else:
                log(credentials['error'], 'ERROR')
                return get_logs()
        
        # try to import the action request in run time, throw an error if fails
        try:
            remediate_module = import_module('remediation_modules.' + event['actionId'])
        except Exception as e:
            log('Cannot import/find module Error e: {0}'.format(str(e)),"ERROR")
            return get_logs()
        
        # if there are extraParams parse them into a dict from JSON
        if('extraParams' in event and event['extraParams']):
            event['extraParams'] = json.loads(event['extraParams'])
        
        # run the remediation action with the session we created and the 
        # event parameters
        response = remediate_module.remediate_action(session, event)

        return response