"""
Test that verifies a role can create an SSM parameter in the /test/ namespace.
"""
import boto3
import pytest
from botocore.exceptions import ClientError
from iam_smoke.tester import assume_role_session, get_role_arn
from iam_smoke.config import DEFAULT_ROLE_NAME, DEFAULT_REGION

# This role is expected to have ssm:PutParameter permission in the /test/ namespace
ROLE_NAME = DEFAULT_ROLE_NAME
TEST_ROLE_ARN = get_role_arn(ROLE_NAME)
ALLOWED_PARAMETER_NAME = "/test/parameter"
PARAMETER_VALUE = "test-value"


@pytest.mark.live
def test_ssm_parameter_create_should_succeed():
    """
    Test that the role can create an SSM parameter in the /test/ namespace.
    """
    session = assume_role_session(TEST_ROLE_ARN, region=DEFAULT_REGION)
    ssm = session.client("ssm")

    try:
        # Attempt to create an SSM parameter in the allowed namespace
        response = ssm.put_parameter(
            Name=ALLOWED_PARAMETER_NAME,
            Value=PARAMETER_VALUE,
            Type="String",
            Overwrite=True
        )
        
        # Verify the parameter was created successfully
        assert "Version" in response
        assert response["Version"] >= 1
        
        # Clean up - delete the parameter
        ssm.delete_parameter(Name=ALLOWED_PARAMETER_NAME)
        
    except ClientError as e:
        pytest.fail(f"Failed to create SSM parameter in /test/ namespace: {str(e)}")
