Excellent — here's the revised and fully detailed testing design based on your updated requirement:


## 🔍 Purpose

Each test should:

1. **Explicitly declare the IAM role** being tested
2. **Assume the role in real AWS**
3. **Attempt a real AWS API action**
4. **Assert success or failure**

---

## 🧪 Example: `tests/test_s3_list_should_succeed.py`

```python
import boto3
import pytest
from botocore.exceptions import ClientError
from iam_smoke.tester import assume_role_session

# This role is expected to have s3:ListBucket permission on the test bucket
TEST_ROLE_ARN = "arn:aws:iam::123456789012:role/s3-list-permitted"
TEST_BUCKET = "my-smoke-test-bucket"

@pytest.mark.live
def test_s3_list_bucket_should_succeed():
    session = assume_role_session(TEST_ROLE_ARN, region="us-east-1")
    s3 = session.client("s3")

    response = s3.list_objects_v2(Bucket=TEST_BUCKET)
    assert "Contents" in response or response["KeyCount"] == 0
```

---

## ❌ Example: `tests/test_s3_get_should_fail.py`

```python
import boto3
import pytest
from botocore.exceptions import ClientError
from iam_smoke.tester import assume_role_session

# This role is expected *not* to have s3:GetObject permission
TEST_ROLE_ARN = "arn:aws:iam::123456789012:role/s3-get-blocked"
TEST_BUCKET = "my-smoke-test-bucket"
OBJECT_KEY = "restricted.txt"

@pytest.mark.live
def test_s3_get_object_should_fail():
    session = assume_role_session(TEST_ROLE_ARN, region="us-east-1")
    s3 = session.client("s3")

    with pytest.raises(ClientError) as e:
        s3.get_object(Bucket=TEST_BUCKET, Key=OBJECT_KEY)

    assert e.value.response["Error"]["Code"] == "AccessDenied"
```

---

## 🛠️ Supporting Code

### `iam_smoke/tester.py`

```python
import boto3

def assume_role_session(role_arn: str, region: str = "us-east-1"):
    sts = boto3.client("sts")
    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="SmokeTestSession"
    )
    creds = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region
    )
```

---

## ✅ Naming Convention for Tests

Name each test file and function to reflect:

* What role is tested
* What action is attempted
* Whether it should pass or fail

**Examples:**

| Filename                           | Action                  | Role                | Expected |
| ---------------------------------- | ----------------------- | ------------------- | -------- |
| `test_s3_list_should_succeed.py`   | `s3:ListBucket`         | `s3-list-permitted` | ✅ Pass   |
| `test_s3_get_should_fail.py`       | `s3:GetObject`          | `s3-get-blocked`    | ❌ Fail   |
| `test_ec2_describe_should_pass.py` | `ec2:DescribeInstances` | `ec2-reader`        | ✅ Pass   |

---
