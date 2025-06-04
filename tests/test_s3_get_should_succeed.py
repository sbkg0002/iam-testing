"""
Test that verifies a role can get an object from an S3 bucket.
"""

import pytest

from iam_smoke.config import DEFAULT_REGION, DEFAULT_ROLE_NAME, DEFAULT_TEST_BUCKET
from iam_smoke.tester import assume_role_session, get_role_arn

# This role is expected to have s3:GetObject permission
ROLE_NAME = DEFAULT_ROLE_NAME
TEST_ROLE_ARN = get_role_arn(ROLE_NAME)
TEST_BUCKET = DEFAULT_TEST_BUCKET
OBJECT_KEY = "restricted.txt"


@pytest.mark.live
def test_s3_get_object_should_succeed():
    """
    Test that the role can get a specific object from the test bucket.
    """
    session = assume_role_session(TEST_ROLE_ARN, region=DEFAULT_REGION)
    s3 = session.client("s3")

    response = s3.get_object(Bucket=TEST_BUCKET, Key=OBJECT_KEY)

    # Verify we got a valid response with object content
    assert "Body" in response
    assert "ContentLength" in response
    assert response["ContentLength"] > 0
