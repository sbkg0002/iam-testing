"""
Test that verifies a role can list objects in an S3 bucket.
"""
import boto3
import pytest
from botocore.exceptions import ClientError
from iam_smoke.tester import assume_role_session, get_role_arn
from iam_smoke.config import DEFAULT_ROLE_NAME, DEFAULT_TEST_BUCKET, DEFAULT_REGION

# This role is expected to have s3:ListBucket permission on the test bucket
# ROLE_NAME = "s3-list-permitted"
ROLE_NAME = DEFAULT_ROLE_NAME

TEST_ROLE_ARN = get_role_arn(ROLE_NAME)
TEST_BUCKET = DEFAULT_TEST_BUCKET


@pytest.mark.live
def test_s3_list_bucket_should_succeed():
    """
    Test that the s3-list-permitted role can list objects in the test bucket.
    """
    session = assume_role_session(TEST_ROLE_ARN, region=DEFAULT_REGION)
    s3 = session.client("s3")

    response = s3.list_objects_v2(Bucket=TEST_BUCKET)
    assert "Contents" in response or response["KeyCount"] == 0
