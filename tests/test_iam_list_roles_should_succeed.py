"""
Test that verifies a role can list IAM roles.
"""
import boto3
import pytest
from botocore.exceptions import ClientError
from iam_smoke.tester import assume_role_session, get_role_arn
from iam_smoke.config import DEFAULT_ROLE_NAME, DEFAULT_REGION

# This role is expected to have iam:ListRoles permission
ROLE_NAME = DEFAULT_ROLE_NAME
TEST_ROLE_ARN = get_role_arn(ROLE_NAME)


@pytest.mark.live
def test_iam_list_roles_should_succeed():
    """
    Test that the role can list IAM roles.
    """
    session = assume_role_session(TEST_ROLE_ARN, region=DEFAULT_REGION)
    iam = session.client("iam")

    response = iam.list_roles()
    
    # Verify we got a valid response
    assert isinstance(response, dict)
    assert "Roles" in response
    # Verify we have at least one role (there should always be at least the role we're using)
    assert len(response["Roles"]) > 0
    # Verify each role has an ARN
    for role in response["Roles"]:
        assert "Arn" in role
        assert role["Arn"].startswith("arn:aws:iam::")
