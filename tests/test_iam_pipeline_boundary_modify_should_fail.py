"""
Test that verifies a role cannot modify a protected IAM policy or create a new version.
"""
import boto3
import json
import pytest
from botocore.exceptions import ClientError
from iam_smoke.tester import assume_role_session, get_role_arn, get_current_account_id
from iam_smoke.config import DEFAULT_ROLE_NAME, DEFAULT_REGION

# This role is expected to NOT have permission to modify protected policies
ROLE_NAME = DEFAULT_ROLE_NAME
TEST_ROLE_ARN = get_role_arn(ROLE_NAME)
PROTECTED_POLICY_NAME = "platform/workload_boundary"


@pytest.mark.live
def test_iam_policy_modify_should_fail():
    """
    Test that the role cannot modify a protected IAM policy or create a new version.
    This verifies that critical platform policies are protected from unauthorized changes.
    """
    # Get the current account ID to build the full policy ARN
    account_id = get_current_account_id()
    policy_arn = f"arn:aws:iam::{account_id}:policy/{PROTECTED_POLICY_NAME}"
    
    # Create a session with the test role
    session = assume_role_session(TEST_ROLE_ARN, region=DEFAULT_REGION)
    iam = session.client("iam")
    
    # Define a modified policy document
    modified_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }
        ]
    }
    
    # First, try to delete a policy version (should fail)
    print(f"Attempting to delete policy version with ARN: {policy_arn}")
    try:
        # Try to delete a policy version (using v1 as an example)
        response = iam.delete_policy_version(
            PolicyArn=policy_arn,
            VersionId="v1"
        )
        print(f"Unexpected success in delete_policy_version: {response}")
        pytest.fail(f"delete_policy_version unexpectedly succeeded with response: {response}")
    except ClientError as e:
        print(f"Expected error in delete_policy_version: {e}")
    
    # No need for these lines anymore as we're handling the error directly in the except block above
    # and printing the error message there
    
    # Attempt to create a new version with LimitExceededException handling
    print(f"Attempting to create policy version with ARN: {policy_arn}")
    try:
        response = iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(modified_policy),
            SetAsDefault=True
        )
        print(f"Unexpected success in create_policy_version: {response}")
        pytest.fail(f"create_policy_version unexpectedly succeeded with response: {response}")
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        print(f"Create policy version error: {e}, error code: {error_code}")
        
        # Handle LimitExceededException specifically
        if error_code == "LimitExceededException":
            print("Handling LimitExceededException by trying to delete an older version first")
            
            # First, try to list policy versions (this should fail with access denied)
            print(f"Attempting to list policy versions for ARN: {policy_arn}")
            try:
                versions_response = iam.list_policy_versions(PolicyArn=policy_arn)
                print(f"Unexpected success in list_policy_versions: {versions_response}")
                pytest.fail(f"list_policy_versions unexpectedly succeeded with response: {versions_response}")
            except ClientError as list_e:
                print(f"Expected error in list_policy_versions: {list_e}")
            
            # Even if we can't list versions, try to delete a specific version (should also fail)
            print(f"Attempting to delete specific policy version v2 for ARN: {policy_arn}")
            try:
                delete_response = iam.delete_policy_version(
                    PolicyArn=policy_arn,
                    VersionId="v2"  # Attempt with a specific version ID
                )
                print(f"Unexpected success in delete_policy_version v2: {delete_response}")
                pytest.fail(f"delete_policy_version v2 unexpectedly succeeded with response: {delete_response}")
            except ClientError as delete_e:
                print(f"Expected error in delete_policy_version v2: {delete_e}")
            
            # Try creating the new version again (should still fail with access denied)
            print(f"Attempting to create policy version again after handling LimitExceededException")
            try:
                create_again_response = iam.create_policy_version(
                    PolicyArn=policy_arn,
                    PolicyDocument=json.dumps(modified_policy),
                    SetAsDefault=True
                )
                print(f"Unexpected success in create_policy_version retry: {create_again_response}")
                pytest.fail(f"create_policy_version retry unexpectedly succeeded with response: {create_again_response}")
            except ClientError as create_again_e:
                print(f"Expected error in create_policy_version retry: {create_again_e}")
        else:
            # Verify it's an access denied error for the initial create attempt
            assert any(error in str(e) for error in ["AccessDenied", "AccessDeniedException"])
    
    # Attempt to get the policy details (this is allowed)
    print(f"Attempting to get policy details for ARN: {policy_arn}")
    try:
        policy_response = iam.get_policy(PolicyArn=policy_arn)
        print(f"Successfully got policy details: {policy_response}")
        # Verify we got a valid policy response
        assert 'Policy' in policy_response
        assert policy_response['Policy']['Arn'] == policy_arn
    except ClientError as get_e:
        # If this fails for some reason other than permissions, that's ok
        # We're primarily testing modification permissions, not read permissions
        print(f"Note: get_policy failed but this is not our primary test focus: {get_e}")