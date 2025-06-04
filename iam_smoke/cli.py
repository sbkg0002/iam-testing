"""
Command-line interface for IAM smoke test setup
"""
import argparse
import logging
from typing import Optional

from iam_smoke.setup import create_test_role, delete_test_role, setup_test_bucket
from iam_smoke.config import DEFAULT_ROLE_NAME, DEFAULT_TEST_BUCKET, DEFAULT_REGION

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def setup_command(args):
    """Handle the setup command"""
    if args.role:
        role_arn = create_test_role(
            region=args.region,
            permission_boundary_arn=args.permission_boundary,
            clone_from_role=args.clone_from_role
        )
        print(f"Created role: {role_arn}")
    
    if args.bucket:
        setup_test_bucket(
            region=args.region
        )
        print(f"Bucket setup complete: {DEFAULT_TEST_BUCKET}")


def teardown_command(args):
    """Handle the teardown command"""
    if args.role:
        success = delete_test_role(
            region=args.region
        )
        if success:
            print(f"Deleted role: {DEFAULT_ROLE_NAME}")
        else:
            print(f"Role {DEFAULT_ROLE_NAME} did not exist")


def main():
    """Main entry point for the CLI"""
    parser = argparse.ArgumentParser(description="IAM Smoke Test Setup CLI")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Setup command
    setup_parser = subparsers.add_parser("setup", help="Set up test resources")
    setup_parser.add_argument("--role", action="store_true", help="Create test IAM role")
    setup_parser.add_argument("--permission-boundary", help="ARN of permission boundary to apply to the role")
    setup_parser.add_argument("--clone-from-role", help="Name of an existing role to clone policies and boundary from")
    setup_parser.add_argument("--bucket", action="store_true", help="Create test S3 bucket")
    setup_parser.add_argument("--region", default=DEFAULT_REGION, help="AWS region for resources")
    setup_parser.set_defaults(func=setup_command)
    
    # Teardown command
    teardown_parser = subparsers.add_parser("teardown", help="Tear down test resources")
    teardown_parser.add_argument("--role", action="store_true", help="Delete test IAM role")
    teardown_parser.add_argument("--region", default=DEFAULT_REGION, help="AWS region for resources")
    teardown_parser.set_defaults(func=teardown_command)
    
    args = parser.parse_args()
    
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
