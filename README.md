
# Cloud Native Protector (CNP) Automated Remediation
Automatically remediate misconfiguration and public exposures in your cloud environment.

##  What is CNP Automated Remediation?
Radware CNP automated remediation allows you to automatically remediate security findings that the system generates using serverless functions in your cloud environment.  
You can create remediation rules with specific configurations to resolve various issues such as public exposures or misconfigurations.  
Once the system identifies an exposure or a misconfiguration warning in one of your onboarded cloud accounts, CNP executes the appropriate remediation rule to resolve the issue.

## How does it work?
You can choose to enable automated remediation on any of your onboarded accounts.  
Initially, you need to set up your primary account which is the account that the AWS Lambda function resides in.  
This is the account that CNP interacts with through the cross-account role and  assumes the cross-account roles in the secondary accounts, and thus be able to perform the actions on their resources.  
After the setup of the primary account, if needed, you can set up additional onboarded accounts by following the secondary account setup.

Once you complete setting up the account you wish to perform automated remediation on, you need to create remediation rules in the CNP portal.  
Remediation rules define what and how you want to rectify or remediate security issues.  
For example, you can choose to remediate publicly exposed RDS databases in a specific account and specific VPC by using a remediation action that disables the database's publicly accessible flag.

When a new exposure or misconfiguration is detected, CNP evaluates the remediation rules configuration, and if a relevant remediation rule is found, it invokes the Lambda function which runs the applicable remediation action on the entity.  
You can review the results of the remediation in the warning itself or the [audit](https://portal.cwp.radwarecloud.com/#/data-center/remediation/manage/audit "audit") section of the module.

## Setup
### Primary account setup
You perform primary account setup only once on the account you want the Lambda function to run on.  
This setup runs a cloud formation stack that does the following:
1. Create the automated remediation Lambda function.
2. Create an IAM role which the Lambda function uses.
3. Create an IAM policy with the needed permissions to run the remediation actions and attach it to the Lambda role.
4. Create a cross-account role which CNP can assume to invoke the Lambda function.

Setup steps:

1. Click the [![Launch Stack](https://cdn.rawgit.com/buildkite/cloudformation-launch-stack-button-svg/master/launch-stack.svg)](https://console.aws.amazon.com/cloudformation/home#/stacks/create/review?templateURL=https://cnp-automated-remediation-us-east-1.s3.amazonaws.com/radware-cft-remediation-primary.yaml&stackName=RadwareCNPPrimaryAccountSetup) button and change the AWS region to where you want to deploy the Lambda code.
2. Fill in the **ExternalID** parameter which you can take from the [CNP portal](https://portal.cwp.radwarecloud.com/#/data-center/remediation/account/setup/aws-account "CNP portal").
3. Under the **Capabilities and transforms** section, click the following checkboxes:
	1. I acknowledge that AWS CloudFormation might create IAM resources.
	2. I acknowledge that AWS CloudFormation might create IAM resources with custom names.
	3. I acknowledge that AWS CloudFormation might require the following capability: CAPABILITY_AUTO_EXPAND.
4. Click on **Create stack**.
5. Once you created a stack, click the **Outputs** tab and extract the values of the fields, **CrossAccountRoleARN** and **LambdaARN**.
6. Go back to the [CNP portal](https://portal.cwp.radwarecloud.com/#/data-center/remediation/account/setup/create-account "CNP portal"), and fill in the cross-account role ARN and Lambda ARN to complete the setup of the primary account.

### Secondary account setup
You perform secondary account setup on any additional accounts you wish to perform automated remediation on.  
This setup runs a cloud formation stack that does the following:
1. Create a cross-account role that can be assumed by the Lambda function which is deployed in the primary account.
2. Create an IAM policy with the needed permissions to run the remediation actions and attach it to the cross-account role.

Setup steps:

1. Click the [![Launch Stack](https://cdn.rawgit.com/buildkite/cloudformation-launch-stack-button-svg/master/launch-stack.svg)](https://console.aws.amazon.com/cloudformation/home#/stacks/create/review?templateURL=https://cnp-automated-remediation-us-east-1.s3.amazonaws.com/radware-cft-remediation-secondary.yaml&stackName=RadwareCNPSecondaryAccountSetup) button and change the AWS region to where you want to run the cloud formation stack in.
2. Fill in the **PrimaryAWSAccountID** parameter with the AWS account ID on which you performed the primary account setup.
3. Under the **Capabilities** section, click the **I acknowledge that AWS CloudFormation might create IAM resources with custom names.** checkbox.
4. Click on **Create stack**.
5. Once you created a stack, you completed the necessary account setup.

Radware CNP automatically detects that you completed the setup for this account and allows you to create remediation rules on it.  
Please note that it might take up to an hour to recognize the setup.


## License
This project is licensed under the MIT License. 
