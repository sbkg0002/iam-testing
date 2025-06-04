"""
Utilities for setting up IAM smoke test resources
"""
import json
import uuid
import logging
from typing import Optional, Dict, Any, List

import boto3
from botocore.exceptions import ClientError

from iam_smoke.config import DEFAULT_ROLE_NAME, DEFAULT_TEST_BUCKET, DEFAULT_REGION

logger = logging.getLogger(__name__)


def create_test_role(
    role_name: str = DEFAULT_ROLE_NAME,
    permissions: List[Dict[str, Any]] = None,
    region: str = DEFAULT_REGION,
    permission_boundary_arn: Optional[str] = None,
    aws_account_id: Optional[str] = None,
    description: str = "IAM smoke test role",
    clone_from_role: Optional[str] = None,
) -> str:
    """
    Create a test IAM role for smoke testing with optional permission boundary.
    
    Args:
        role_name: Name of the role to create
        permissions: List of IAM policy documents to attach
        region: AWS region
        permission_boundary_arn: ARN of permission boundary policy to apply (optional)
        aws_account_id: AWS account ID (if None, uses current account)
        description: Role description
        clone_from_role: Name of an existing role to clone policies and boundary from (optional)
        
    Returns:
        str: ARN of the created role
    """
    # Create IAM client
    iam = boto3.client("iam", region_name=region)
    
    # If cloning from an existing role, get its policies and boundary
    cloned_policies = []
    cloned_boundary_arn = None
    
    if clone_from_role:
        logger.info(f"Cloning policies and boundary from role: {clone_from_role}")
        try:
            # Get the role to check if it exists and get its permission boundary
            role_response = iam.get_role(RoleName=clone_from_role)
            role_data = role_response.get('Role', {})
            
            # Get the permission boundary if it exists
            if 'PermissionsBoundary' in role_data:
                cloned_boundary_arn = role_data['PermissionsBoundary'].get('PermissionsBoundaryArn')
                logger.info(f"Cloned permission boundary: {cloned_boundary_arn}")
                
                # Use the cloned boundary unless explicitly overridden
                if permission_boundary_arn is None:
                    permission_boundary_arn = cloned_boundary_arn
            
            # Get inline policies
            policy_names_response = iam.list_role_policies(RoleName=clone_from_role)
            policy_names = policy_names_response.get('PolicyNames', [])
            
            for policy_name in policy_names:
                policy_response = iam.get_role_policy(
                    RoleName=clone_from_role,
                    PolicyName=policy_name
                )
                
                # Convert the policy document from URL-encoded JSON to a dictionary
                policy_doc = json.loads(policy_response.get('PolicyDocument'))
                cloned_policies.append(policy_doc)
                logger.info(f"Cloned inline policy: {policy_name}")
            
            # Get attached managed policies
            managed_policies_response = iam.list_attached_role_policies(RoleName=clone_from_role)
            managed_policies = managed_policies_response.get('AttachedPolicies', [])
            
            # We'll store the ARNs of managed policies to attach later
            managed_policy_arns = [policy['PolicyArn'] for policy in managed_policies]
            
        except ClientError as e:
            logger.error(f"Error cloning from role {clone_from_role}: {str(e)}")
            raise
    
    # Use cloned policies if available and no explicit policies provided
    if permissions is None:
        if cloned_policies:
            permissions = cloned_policies
        else:
            # Default permissions for smoke testing if not cloning
            permissions = [
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "*"
                            ],
                            "Resource": "*"
                        }
                    ]
                }
            ]
    
    # If account ID not provided, get the current account ID
    if aws_account_id is None:
        sts = boto3.client("sts", region_name=region)
        aws_account_id = sts.get_caller_identity()["Account"]
        
    # Create assume role policy document
    assume_role_policy_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{aws_account_id}:root"},
                "Action": "sts:AssumeRole"
            }
        ]
    })
    
    try:
        # Check if role already exists
        try:
            iam.get_role(RoleName=role_name)
            logger.info(f"Role {role_name} already exists")
            delete_test_role(role_name, region)
            logger.info(f"Deleted existing role {role_name} to recreate it")
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise
        
        # Create the role
        create_params = {
            "RoleName": role_name,
            "AssumeRolePolicyDocument": assume_role_policy_document,
            "Description": description,
            "Tags": [
                {"Key": "Purpose", "Value": "IAM-Smoke-Testing"},
                {"Key": "Temporary", "Value": "True"}
            ]
        }
        
        # Add permission boundary if specified
        if permission_boundary_arn:
            create_params["PermissionsBoundary"] = permission_boundary_arn
            
        role = iam.create_role(**create_params)
        role_arn = role["Role"]["Arn"]
        logger.info(f"Created role {role_name} with ARN {role_arn}")
        
        # Attach inline policies
        for i, policy_doc in enumerate(permissions):
            policy_name = f"{role_name}-policy-{i}"
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_doc)
            )
            logger.info(f"Attached inline policy {policy_name} to role {role_name}")
        
        # Attach managed policies if we cloned from an existing role
        if clone_from_role and 'managed_policy_arns' in locals():
            for policy_arn in managed_policy_arns:
                try:
                    iam.attach_role_policy(
                        RoleName=role_name,
                        PolicyArn=policy_arn
                    )
                    logger.info(f"Attached managed policy {policy_arn} to role {role_name}")
                except ClientError as e:
                    logger.warning(f"Failed to attach managed policy {policy_arn}: {str(e)}")
            
        return role_arn
        
    except Exception as e:
        logger.error(f"Error creating test role {role_name}: {str(e)}")
        raise


def delete_test_role(role_name: str = DEFAULT_ROLE_NAME, region: str = DEFAULT_REGION) -> bool:
    """
    Delete a test IAM role used for smoke testing.
    
    Args:
        role_name: Name of the role to delete
        region: AWS region
        
    Returns:
        bool: True if role was deleted, False if it didn't exist
    """
    iam = boto3.client("iam", region_name=region)
    
    try:
        # First we need to delete all inline policies
        response = iam.list_role_policies(RoleName=role_name)
        for policy_name in response["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            logger.info(f"Deleted inline policy {policy_name} from role {role_name}")
        
        # Detach all managed policies
        managed_policies_response = iam.list_attached_role_policies(RoleName=role_name)
        for policy in managed_policies_response.get('AttachedPolicies', []):
            policy_arn = policy['PolicyArn']
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            logger.info(f"Detached managed policy {policy_arn} from role {role_name}")
        
        # Then we can delete the role
        iam.delete_role(RoleName=role_name)
        logger.info(f"Deleted role {role_name}")
        return True
        
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            logger.info(f"Role {role_name} does not exist, nothing to delete")
            return False
        else:
            logger.error(f"Error deleting test role {role_name}: {str(e)}")
            raise


def create_random_test_role(
    prefix: str = "TestRole",
    permissions: List[Dict[str, Any]] = None,
    region: str = DEFAULT_REGION,
    permission_boundary_arn: Optional[str] = None,
) -> tuple:
    """
    Create a test IAM role with a random name for smoke testing.
    
    Args:
        prefix: Prefix for the role name
        permissions: List of IAM policy documents to attach
        region: AWS region
        permission_boundary_arn: ARN of permission boundary policy to apply (optional)
        
    Returns:
        tuple: (role_name, role_arn)
    """
    # Generate a random role name
    random_suffix = uuid.uuid4().hex[:8]
    role_name = f"{prefix}{random_suffix}"
    
    role_arn = create_test_role(
        role_name=role_name,
        permissions=permissions,
        region=region,
        permission_boundary_arn=permission_boundary_arn
    )
    
    return role_name, role_arn


def setup_test_bucket(bucket_name: str = DEFAULT_TEST_BUCKET, region: str = DEFAULT_REGION) -> str:
    """
    Create a test S3 bucket for smoke testing if it doesn't exist.
    
    Args:
        bucket_name: Name of the bucket to create
        region: AWS region
        
    Returns:
        str: The name of the bucket that was created or verified
    """
    # Ensure bucket name is unique by adding account ID suffix if needed
    original_bucket_name = bucket_name
    s3 = boto3.client("s3", region_name=region)
    
    # Get AWS account ID for uniqueness
    sts = boto3.client("sts", region_name=region)
    account_id = sts.get_caller_identity()["Account"]
    
    try:
        # Check if bucket exists
        s3.head_bucket(Bucket=bucket_name)
        logger.info(f"Bucket {bucket_name} already exists and is accessible")
        return bucket_name
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        
        # If forbidden (403) or no such bucket (404), create a new bucket with unique name
        if error_code == "403" or error_code == "404" or error_code == "NoSuchBucket":
            # Make bucket name unique with account ID and random suffix
            if error_code == "403":
                logger.warning(f"Bucket {bucket_name} exists but is not accessible, creating a unique bucket")
                # Create a unique name based on original + account ID + random suffix
                random_suffix = uuid.uuid4().hex[:8]
                bucket_name = f"{original_bucket_name}-{account_id}-{random_suffix}".lower()
            
            # Create the bucket
            try:
                if region == "us-east-1":
                    s3.create_bucket(Bucket=bucket_name)
                else:
                    s3.create_bucket(
                        Bucket=bucket_name,
                        CreateBucketConfiguration={
                            "LocationConstraint": region
                        }
                    )
                logger.info(f"Created bucket {bucket_name} in region {region}")
                
                # Add a test object
                s3.put_object(
                    Bucket=bucket_name,
                    Key="restricted.txt",
                    Body="This is a restricted test file."
                )
                logger.info(f"Added test object 'restricted.txt' to bucket {bucket_name}")
                return bucket_name
            except ClientError as e:
                logger.error(f"Error creating bucket or adding test object: {str(e)}")
                raise
        else:
            logger.error(f"Error checking bucket {bucket_name}: {str(e)}")
            raise
