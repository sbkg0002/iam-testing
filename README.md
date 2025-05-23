# AWS IAM Smoke Testing Framework

A framework for creating and running smoke tests against AWS IAM roles and policies to verify they grant or deny the expected permissions.

## 🔄 Workflow

The framework follows this workflow for smoke testing IAM permissions:

1. **Create Test Resources** - Set up IAM roles and S3 buckets for testing
2. **Assume IAM Role** - Use AWS STS to get temporary credentials
3. **Execute API Calls** - Perform operations against AWS services
4. **Assert Results** - Verify expected outcomes (success or failure)

The diagram above illustrates the flow of the IAM smoke testing process. For more details, see the [full workflow documentation](docs/iam-smoke-workflow.md).

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

## 🔧 Setting Up Test Resources

This framework includes CLI tools to create and manage the test resources needed for IAM smoke testing.

### Command-line Interface (CLI)

The framework provides a command-line tool `iam-smoke` with the following commands:

```bash
# Show help and available commands
uv run iam-smoke --help

# Show help for a specific command
uv run iam-smoke setup --help
uv run iam-smoke teardown --help
```

#### Setting up resources

```bash
# Create the default test role with standard permissions
uv run iam-smoke setup --role

# Create a test role with a permission boundary
uv run iam-smoke setup --role --permission-boundary arn:aws:iam::123456789012:policy/MyBoundary

# Use a custom role name
uv run iam-smoke setup --role --role-name CustomRoleName

# Create the default test S3 bucket
uv run iam-smoke setup --bucket

# Create a custom S3 bucket
uv run iam-smoke setup --bucket --bucket-name my-custom-bucket

# Create both role and bucket in one command
uv run iam-smoke setup --role --bucket

# Specify a custom region for resources
uv run iam-smoke setup --role --bucket --region eu-west-1
```

#### Cleaning Up Resources

```bash
# Remove the default test role
uv run iam-smoke teardown --role

# Remove a custom test role
uv run iam-smoke teardown --role --role-name CustomRoleName
```

### Programmatic Resource Management

You can also create and manage test resources programmatically:

```python
from iam_smoke.setup import create_test_role, setup_test_bucket, delete_test_role

# Create a role with default permissions
role_arn = create_test_role()

# Create a role with a permission boundary
role_arn = create_test_role(
    permission_boundary_arn="arn:aws:iam::123456789012:policy/MyBoundary"
)

# Create a test bucket
setup_test_bucket(bucket_name="my-test-bucket", region="eu-central-1")

# Clean up resources
delete_test_role(role_name="TestRoleName")
```

## 🧪 Writing Tests

All tests use a centralized configuration from `iam_smoke/config.py` that defines the default role name, region, and other settings.

### Included Test Cases

The framework includes the following test cases:

| Filename                              | Action                  | Expected | Description |
| ------------------------------------- | ----------------------- | -------- | ----------- |
| `test_s3_list_should_succeed.py`      | `s3:ListBucket`         | ✅ Pass   | Verifies the role can list objects in an S3 bucket |
| `test_s3_get_should_succeed.py`       | `s3:GetObject`          | ✅ Pass   | Verifies the role can get an object from the test bucket |
| `test_ec2_describe_should_pass.py`    | `ec2:DescribeInstances` | ✅ Pass   | Verifies the role can describe EC2 instances |
| `test_iam_list_roles_should_succeed.py` | `iam:ListRoles`       | ✅ Pass   | Verifies the role can list IAM roles |
| `test_iam_create_admin_role_should_fail.py` | `iam:CreateRole` with admin privileges | ❌ Fail | Verifies the role cannot create admin roles without permission boundaries |
| `test_ssm_parameter_create_should_succeed.py` | `ssm:PutParameter` in `/test/` namespace | ✅ Pass | Verifies the role can create SSM parameters in the allowed namespace |
| `test_ssm_parameter_create_should_fail.py` | `ssm:PutParameter` in `/platform/` namespace | ❌ Fail | Verifies the role cannot create SSM parameters in the restricted namespace |

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
uv run python -m pytest -m live -v
```

To run a specific test file:

```bash
uv run python -m pytest tests/test_s3_list_should_succeed.py -v
```

## 🔒 Security Best Practices

1. Never hardcode actual AWS credentials in test files
2. Set up a dedicated test environment with minimal permissions
3. Use temporary credentials via role assumption
4. Consider using environment variables for role ARNs in CI/CD
