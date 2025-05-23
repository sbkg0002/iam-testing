"""
Test that verifies a role cannot create an SSM parameter in a restricted region (us-west-1).
"""
import boto3
import pytest
from botocore.exceptions import ClientError
from iam_smoke.tester import assume_role_session, get_role_arn
from iam_smoke.config import DEFAULT_ROLE_NAME

# This role is expected to NOT have ssm:PutParameter permission in us-west-1 region
ROLE_NAME = DEFAULT_ROLE_NAME
TEST_ROLE_ARN = get_role_arn(ROLE_NAME)
RESTRICTED_REGION = "us-west-1"
PARAMETER_NAME = "simple-parameter-without-path"
PARAMETER_VALUE = "test-value"


@pytest.mark.live
def test_ssm_parameter_region_should_fail():
    """
    Test that the role cannot create an SSM parameter in the us-west-1 region.
    This test verifies region-based restrictions in IAM policies.
    """
    # Create a session in the restricted region
    session = assume_role_session(TEST_ROLE_ARN, region=RESTRICTED_REGION)
    ssm = session.client("ssm")

    # Attempt to create an SSM parameter in the restricted region
    # This should fail with an AccessDeniedException
    with pytest.raises(ClientError) as excinfo:
        ssm.put_parameter(
            Name=PARAMETER_NAME,
            Value=PARAMETER_VALUE,
            Type="String",
            Overwrite=True
        )
    
    # Verify that the exception is specifically an access denied error
    assert "AccessDenied" in str(excinfo.value) or "AccessDeniedException" in str(excinfo.value)
    # The error message should indicate it's related to region restrictions
    assert "region" in str(excinfo.value).lower() or "location" in str(excinfo.value).lower() or "not authorized" in str(excinfo.value).lower()
