"""
Test that verifies a role can describe EC2 instances.
"""

import pytest

from iam_smoke.config import DEFAULT_REGION, DEFAULT_ROLE_NAME
from iam_smoke.tester import assume_role_session, get_role_arn

# This role is expected to have ec2:DescribeInstances permission
ROLE_NAME = DEFAULT_ROLE_NAME
TEST_ROLE_ARN = get_role_arn(ROLE_NAME)


@pytest.mark.live
def test_ec2_describe_instances_should_pass():
    """
    Test that the ec2-reader role can describe EC2 instances.
    """
    session = assume_role_session(TEST_ROLE_ARN, region=DEFAULT_REGION)
    ec2 = session.client("ec2")

    response = ec2.describe_instances()
    assert isinstance(response, dict)
    assert "Reservations" in response
