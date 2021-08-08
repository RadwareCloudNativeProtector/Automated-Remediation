# Remediation Actions

## Block all public access to S3 bucket 
- Description: Enables the block public access settings to prevent current and future public exposures originating from the bucket policy and ACL. 
- Required permissions: 
	- S3:PutBucketPublicAccessBlock 
- Filename: block_s3_public_access.py

## Stop EC2 instance 
- Description:  Stops a running EC2 instance. 
- Required permissions: 
	- EC2:StopInstances 
- Filename: stop_ec2_instance.py

## Remove ingress rule from security group
- Description: Removes any ingress rule from the security group that is publicly exposed to the ports provided in the parameters section.  
 Note that if we need to remove a port that is part of a range (for example, port 22 from range 20-25), we split the rule into two rules so that you now have ranges 20-21 and 23-25.
You can choose any combination of the following parameters:
	- All Ports - Removes an ingress rule that exposes all ports.
	- This could be the case of a TCP/UDP protocol exposing ports 0-65535 or the specific security group settings of “All traffic” which means all ports in all of the protocols.
	- SSH/RDP - Removes an ingress rule that exposes ports 22 (SSH) or 3389 (RDP).
	- Administrative Ports - Removes an ingress rule that exposes the following ports: 20-21, 23, 115, 137-139, 2049, 1029, 1521, 3306, 5432, 53, 1433, 445, 9200, 27017.
	- Specific Ports - Removes an ingress rule that exposes any of the provided ports.
You can add multiple ports or port ranges separated by a comma.
- Required permissions:
	- EC2:RevokeSecurityGroupIngress
	- EC2:AuthorizeSecurityGroupIngress
	- EC2:DescribeSecurityGroups
- Filename: remove_ingress_rule_sg.py

## Remove exposed database (RDS/Redshift) server port from security group 

- Description: Removes any ingress rule from the security group that publicly exposes an RDS/Redshift server listening port.  
Note that if we need to remove a port that is part of a range (for example, port 3306 from range 3300-3400), we split the rule into two rules so that you now have ranges 3300-3005 and 3007-3400.
- Required permissions:
	- EC2:RevokeSecurityGroupIngress
	- EC2:AuthorizeSecurityGroupIngress
	- EC2:DescribeSecurityGroups
- Filename: remove_rds_redshift_port_sg.py

## Disable RDS server publicly accessible flag
- Description:  Sets the RDS server publicly accessible flag to false.
- Required permissions:
	- rds:ModifyDBInstance
- Filename: block_rds_public_access.py

## Disable Redshift cluster publicly accessible flag
- Description: Sets the Redshift cluster publicly accessible flag to false.
- Required permissions:
	- redshift:ModifyCluster
- Filename: block_redshift_public_access.py

## Disable user inactive access key
- Description: Disables a user's inactive access key.  
 You can choose any combination of the following parameters:
	- AccessKey1 – Disables the first access key.
	- AccessKey2 – Disables the second access key.
- Required permissions:
	- IAM:UpdateAccessKey
	- IAM:ListAccessKeys
- Filename: disable_inactive_access_keys.py

## Block specific public access to S3 bucket

- Description: Removes a specific type of bucket public permissions as provided in the parameters.  
You can choose any combination of the following parameters:
	- 	List – Removes list permissions from the bucket policy and ACL.
	- 	Read – Removes read permissions from the bucket policy.
	- 	Write – Removes write permissions from the bucket policy and ACL.
	- 	Manage – Removes manage permissions from the bucket policy and ACL.
- Required permissions:
	- s3:GetBucketAcl
	- s3:PutBucketAcl
	- s3:GetBucketPolicy
	- s3:DeleteBucketPolicy
	- s3:PutBucketPolicy
- Filename: block_specific_s3_public_access.py

## Disable user console access

- Description: Disables a user console access by deleting it. 
- Required permissions:
	- IAM:DeleteLoginProfile
- Filename: disable_console_access.py

## Enable key rotation for customer-managed key (CMK)
- Description: Enables key rotation for a KMS key that is managed by a customer (CMK).
- Required permissions:
	- KMS:EnableKeyRotation
- Filename: enable_key_rotation.py

## Enforce strong account password policy

- Description: Enforces strong account password policy as defined in AWS CIS benchmark.  
The enforcement includes:
	- Password must consist of at least one number, symbol, uppercase character, and lowercase character.
	- Password length of at least 14 characters.
	- Password resetting every 3 months and password cannot be reused.
- Required permissions:
	- iam:GetAccountPasswordPolicy
	- iam:UpdateAccountPasswordPolicy
- Filename: enforce_account_password_policy.py

## Quarantine IAM user
- Description: Quarantines an IAM user by disabling the user’s access keys and console access login.  
You can choose any combination of the following parameters:
	- DeleteConsoleAccess – Deletes the IAM user console access if it exists.
	- DisableAccessKeys – Disables access keys 1 and 2 if they exist.
- Required permissions:
	- IAM:UpdateAccessKey
	- IAM:DeleteLoginProfile
	- IAM:ListAccessKeys
- Filename: quarantine_user.py

## Remove public exposure of Amazon Machine Image (AMI)
- Description: Removes the setting that exposes the Amazon Machine Image (AMI) to the public.
- Required permissions:
	- ec2:ModifyImageAttribute
- Filename: remove_ami_public_exposure.py

## Remove public exposure of RDS instance snapshot
- Description: Removes the setting that exposes the RDS instance snapshot to the public.
- Required permissions:
	- rds:ModifyDBSnapshotAttribute
- Filename: emove_rds_instance_snapshot_public_access.py

## Remove public exposure of RDS cluster snapshot
- Description: Removes the setting that exposes the RDS cluster snapshot to the public.
- Required permissions:
	- rds:ModifyDBClusterSnapshotAttribute
- Filename: remove_rds_cluster_snapshot_public_access.py

## Restrict all traffic from default security groups
- Description: Removes all ingress/egress rules from the default security groups.
- Required permissions:
	- EC2:RevokeSecurityGroupIngress
	- EC2:RevokeSecurityGroupEgress
	- EC2:DescribeSecurityGroups
- Filename: restrict_all_traffic_default_sg.py

## Enable CloudTrail multi-region logging
- Description: Enables multi-region logging for a CloudTrail.
- Required permissions:
	- cloudtrail:UpdateTrail
- Filename: enable_multi_region_cloudtrail.py


## Enable S3 bucket server-side encryption
- Description: Enables server-side encryption (AES256) for an S3 bucket.
- Required permissions:
	- s3:PutEncryptionConfiguration
- Filename: enable_s3_server_side_encryption.py

## Enable CloudTrail log validation
- Description: Enables log validation for a CloudTrail.
- Required permissions:
	- cloudtrail:UpdateTrail
- Filename: enable_log_validation_cloudtrail.py
