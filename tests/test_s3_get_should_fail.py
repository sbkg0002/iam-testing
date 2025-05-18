"""
Test that verifies a role cannot get an object from an S3 bucket.
"""
import boto3
import pytest
from botocore.exceptions import ClientError
from iam_smoke.tester import assume_role_session, get_role_arn
from iam_smoke.config import DEFAULT_ROLE_NAME, DEFAULT_TEST_BUCKET, DEFAULT_REGION

# This role is expected *not* to have s3:GetObject permission
# ROLE_NAME = "s3-get-blocked"
ROLE_NAME = DEFAULT_ROLE_NAME

TEST_ROLE_ARN = get_role_arn(ROLE_NAME)
TEST_BUCKET = DEFAULT_TEST_BUCKET
OBJECT_KEY = "restricted.txt"


@pytest.mark.live
def test_s3_get_object_should_fail():
    """
    Test that the s3-get-blocked role cannot get a specific object from the test bucket.
    """
    session = assume_role_session(TEST_ROLE_ARN, region=DEFAULT_REGION)
    s3 = session.client("s3")

    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=TEST_BUCKET, Key=OBJECT_KEY)

    assert e.value.response["Error"]["Code"] == "AccessDenied"
