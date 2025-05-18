"""
IAM smoke testing utilities
"""
import boto3
from typing import Optional


def get_current_account_id():
    """
    Get the AWS account ID from the current session credentials
    
    Returns:
        str: The AWS account ID
    """
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Account"]


def get_role_arn(role_name: str, account_id: str = None):
    """
    Build a full role ARN using the given role name and account ID
    
    Args:
        role_name: The name of the IAM role
        account_id: The AWS account ID. If None, uses the current account ID
        
    Returns:
        str: The complete role ARN
    """
    if account_id is None:
        account_id = get_current_account_id()
    
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def assume_role_session(role_arn: str, region: str = "us-east-1", session_name: str = "SmokeTestSession"):
    """
    Assume an IAM role and return a boto3 session with the temporary credentials.
    
    Args:
        role_arn: The ARN of the role to assume
        region: The AWS region to use for the session
        session_name: The session name to use when assuming the role
        
    Returns:
        boto3.Session: A boto3 session configured with temporary credentials
    """
    sts = boto3.client("sts")
    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name
    )
    creds = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region
    )
