"""
Test that verifies a role cannot create an administrator role without a permission boundary.
This is an important security control to prevent privilege escalation.
"""
import boto3
import pytest
from botocore.exceptions import ClientError
from iam_smoke.tester import assume_role_session, get_role_arn
from iam_smoke.config import DEFAULT_ROLE_NAME, DEFAULT_REGION
import json
import uuid

# This role should not be able to create admin roles without permission boundaries
ROLE_NAME = DEFAULT_ROLE_NAME
TEST_ROLE_ARN = get_role_arn(ROLE_NAME)


@pytest.mark.live
def test_iam_create_admin_role_without_boundary_should_fail():
    """
    Test that verifies creating an IAM role with administrator privileges fails
    when no permission boundary is specified.
    
    This test attempts to create a role with the AdministratorAccess policy,
    which should be blocked unless a permission boundary is applied.
    """
    # Create a session with the test role
    session = assume_role_session(TEST_ROLE_ARN, region=DEFAULT_REGION)
    iam = session.client("iam")
    
    # Generate a random name for the test role to avoid conflicts
    random_suffix = uuid.uuid4().hex[:8]
    admin_role_name = f"TestAdminRole{random_suffix}"
    
    # Create assume role policy document for the new role
    assume_role_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    })
    
    # Attempt to create the role without a permission boundary
    with pytest.raises(ClientError) as e:
        iam.create_role(
            RoleName=admin_role_name,
            AssumeRolePolicyDocument=assume_role_policy,
            Description="Test role with admin access - should fail without boundary",
            Tags=[
                {"Key": "Purpose", "Value": "IAM-Smoke-Testing"},
                {"Key": "Temporary", "Value": "True"}
            ]
        )
        
        # If role creation succeeds, try to attach admin policy (this should also fail)
        iam.attach_role_policy(
            RoleName=admin_role_name,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
        )
    
    # Verify the error is related to permissions or boundaries
    error_code = e.value.response["Error"]["Code"]
    print(f'{e.value.response=}')
    assert error_code in ["AccessDenied", "UnauthorizedOperation"], \
           f"Expected AccessDenied or UnauthorizedOperation, got {error_code}"
    
    # Cleanup in case the test failed and the role was created
    try:
        iam.detach_role_policy(
            RoleName=admin_role_name,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
        )
        iam.delete_role(RoleName=admin_role_name)
    except ClientError:
        # Ignore errors during cleanup
        pass
