# AWS IAM Smoke Testing Framework

A framework for creating and running smoke tests against AWS IAM roles and policies to verify they grant or deny the expected permissions.

## 🔍 Purpose

This framework allows you to:

1. **Explicitly declare the IAM role** being tested
2. **Assume the role in real AWS**
3. **Attempt a real AWS API action**
4. **Assert success or failure**

## 🛠️ Requirements

- Python 3.11 or higher
- uv (for package and environment management)
- ruff (for code formatting and linting)
- AWS credentials with `sts:AssumeRole` permissions to the roles being tested

## 📦 Installation

Using uv for environment and package management:

```bash
# Create a new environment
uv venv

# Activate the environment
source .venv/bin/activate  # On Unix/macOS
# OR
.venv\Scripts\activate     # On Windows

# Install the package and dependencies
uv pip install -e .
```

## 🧪 Writing Tests

Follow the naming convention for tests:

| Filename                           | Action                  | Role                | Expected |
| ---------------------------------- | ----------------------- | ------------------- | -------- |
| `test_s3_list_should_succeed.py`   | `s3:ListBucket`         | `s3-list-permitted` | ✅ Pass   |
| `test_s3_get_should_fail.py`       | `s3:GetObject`          | `s3-get-blocked`    | ❌ Fail   |
| `test_ec2_describe_should_pass.py` | `ec2:DescribeInstances` | `ec2-reader`        | ✅ Pass   |

### Test Template for Successful Action

```python
import boto3
import pytest
from iam_smoke.tester import assume_role_session, get_role_arn

# Role name will be paired with your current AWS account ID
ROLE_NAME = "YOUR-ROLE-NAME"
TEST_ROLE_ARN = get_role_arn(ROLE_NAME)

@pytest.mark.live
def test_action_should_succeed():
    session = assume_role_session(TEST_ROLE_ARN)
    client = session.client("SERVICE")
    
    response = client.ACTION()
    assert EXPECTED_CONDITION
```

### Test Template for Failed Action

```python
import boto3
import pytest
from botocore.exceptions import ClientError
from iam_smoke.tester import assume_role_session, get_role_arn

# Role name will be paired with your current AWS account ID
ROLE_NAME = "YOUR-ROLE-NAME"
TEST_ROLE_ARN = get_role_arn(ROLE_NAME)

@pytest.mark.live
def test_action_should_fail():
    session = assume_role_session(TEST_ROLE_ARN)
    client = session.client("SERVICE")
    
    with pytest.raises(ClientError) as e:
        client.ACTION()
        
    assert e.value.response["Error"]["Code"] == "AccessDenied"
```

## 🚀 Running Tests

To run all live tests:

```bash
uv pip install pytest
python -m pytest -m live -v
```

To run a specific test file:

```bash
python -m pytest tests/test_s3_list_should_succeed.py -v
```

## 🔒 Security Best Practices

1. Never hardcode actual AWS credentials in test files
2. Set up a dedicated test environment with minimal permissions
3. Use temporary credentials via role assumption
4. Consider using environment variables for role ARNs in CI/CD
