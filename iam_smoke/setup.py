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
    trust_principal: str = "arn:aws:iam::*:root",
    description: str = "IAM smoke test role",
) -> str:
    """
    Create a test IAM role for smoke testing with optional permission boundary.
    
    Args:
        role_name: Name of the role to create
        permissions: List of IAM policy documents to attach
        region: AWS region
        permission_boundary_arn: ARN of permission boundary policy to apply (optional)
        trust_principal: Principal allowed to assume the role
        description: Role description
        
    Returns:
        str: ARN of the created role
    """
    if permissions is None:
        # Default permissions for smoke testing
        permissions = [
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:ListBucket",
                            "s3:GetObject",
                            "ec2:DescribeInstances",
                            "iam:ListRoles"
                        ],
                        "Resource": "*"
                    }
                ]
            }
        ]
    
    # Create assume role policy document
    assume_role_policy_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": trust_principal},
                "Action": "sts:AssumeRole"
            }
        ]
    })
    
    # Create IAM client
    iam = boto3.client("iam", region_name=region)
    
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


def setup_test_bucket(bucket_name: str = DEFAULT_TEST_BUCKET, region: str = DEFAULT_REGION) -> None:
    """
    Create a test S3 bucket for smoke testing if it doesn't exist.
    
    Args:
        bucket_name: Name of the bucket to create
        region: AWS region
    """
    s3 = boto3.client("s3", region_name=region)
    
    try:
        # Check if bucket exists
        s3.head_bucket(Bucket=bucket_name)
        logger.info(f"Bucket {bucket_name} already exists")
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "404" or error_code == "NoSuchBucket":
            # Create the bucket
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
        else:
            logger.error(f"Error checking bucket {bucket_name}: {str(e)}")
            raise
