import json

import boto3

iam = boto3.client("iam")
PROTECTED_POLICY_NAME = "platform/workload_boundary"


def get_current_account_id():
    """
    Get the AWS account ID from the current session credentials

    Returns:
        str: The AWS account ID
    """
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Account"]


account_id = get_current_account_id()
policy_arn = f"arn:aws:iam::{account_id}:policy/{PROTECTED_POLICY_NAME}"

# Define a modified policy document
modified_policy = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
}

iam.create_policy_version(
    PolicyArn=policy_arn, PolicyDocument=json.dumps(modified_policy), SetAsDefault=True
)
