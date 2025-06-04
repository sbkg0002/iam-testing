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
    print("\n==== S3 List Bucket Test Debug Information ====")
    print(f"Using role name: {ROLE_NAME}")
    print(f"Role ARN: {TEST_ROLE_ARN}")
    print(f"Target bucket: {TEST_BUCKET}")
    print(f"AWS Region: {DEFAULT_REGION}")
    
    # Get the current identity before assuming the role
    try:
        sts_direct = boto3.client('sts', region_name=DEFAULT_REGION)
        caller_identity = sts_direct.get_caller_identity()
        print(f"Current identity before assuming role: {caller_identity}")
    except Exception as e:
        print(f"Error getting current identity: {str(e)}")
    
    # Assume the role with detailed logging
    print("Attempting to assume role...")
    try:
        session = assume_role_session(TEST_ROLE_ARN, region=DEFAULT_REGION)
        print("Role assumption successful")
        
        # Verify the identity after assuming the role
        try:
            sts = session.client('sts')
            assumed_identity = sts.get_caller_identity()
            print(f"Identity after assuming role: {assumed_identity}")
        except Exception as e:
            print(f"Error getting assumed identity: {str(e)}")
            
        # Create the S3 client
        print("Creating S3 client...")
        s3 = session.client("s3")
        
        # Try to list buckets first to check general S3 access
        print("Attempting to list all buckets (to check general S3 access)...")
        try:
            all_buckets = s3.list_buckets()
            print(f"List buckets successful. Found {len(all_buckets.get('Buckets', []))} buckets")
            print(f"Bucket names: {[b['Name'] for b in all_buckets.get('Buckets', [])]}")
        except Exception as e:
            print(f"Error listing all buckets: {str(e)}")
        
        # Now try the specific bucket list operation
        print(f"Attempting to list objects in bucket: {TEST_BUCKET}...")
        response = s3.list_objects_v2(Bucket=TEST_BUCKET)
        
        # Print the response details
        print(f"List objects response: {response}")
        if "Contents" in response:
            print(f"Found {len(response['Contents'])} objects in the bucket")
            print(f"First few objects: {[obj['Key'] for obj in response['Contents'][:5]]}")
        else:
            print(f"Bucket appears to be empty. KeyCount: {response.get('KeyCount', 'N/A')}")
        
        # Run the assertion
        assert "Contents" in response or response["KeyCount"] == 0
        print("Test passed successfully!")
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', 'No message')
        print(f"ClientError encountered: {error_code} - {error_message}")
        print(f"Full error: {e}")
        raise
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        raise
    finally:
        print("==== End of S3 List Bucket Test Debug Information ====")
