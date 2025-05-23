"""
Test that verifies a role cannot create an SSM parameter in the /platform/ namespace.
"""
import boto3
import pytest
from botocore.exceptions import ClientError
from iam_smoke.tester import assume_role_session, get_role_arn
from iam_smoke.config import DEFAULT_ROLE_NAME, DEFAULT_REGION

# This role is expected to NOT have ssm:PutParameter permission in the /platform/ namespace
ROLE_NAME = DEFAULT_ROLE_NAME
TEST_ROLE_ARN = get_role_arn(ROLE_NAME)
RESTRICTED_PARAMETER_NAME = "/platform/test/parameter"
PARAMETER_VALUE = "test-value"


@pytest.mark.live
def test_ssm_parameter_create_should_fail():
    """
    Test that the role cannot create an SSM parameter in the /platform/ namespace.
    """
    session = assume_role_session(TEST_ROLE_ARN, region=DEFAULT_REGION)
    ssm = session.client("ssm")

    # Attempt to create an SSM parameter in the restricted namespace
    # This should fail with an AccessDeniedException
    with pytest.raises(ClientError) as excinfo:
        ssm.put_parameter(
            Name=RESTRICTED_PARAMETER_NAME,
            Value=PARAMETER_VALUE,
            Type="String",
            Overwrite=True
        )
    
    # Verify that the exception is specifically an access denied error
    assert "AccessDenied" in str(excinfo.value) or "AccessDeniedException" in str(excinfo.value)
    assert "not authorized" in str(excinfo.value).lower() or "permission" in str(excinfo.value).lower()
