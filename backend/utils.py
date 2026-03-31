import re
import boto3
from botocore.exceptions import ClientError
from exceptions import InvalidRoleARNError, AssumeRoleError

def validate_role_arn(role_arn: str):
    pattern = r"^arn:aws:iam::\d{12}:role/.+$"
    if not re.match(pattern, role_arn.strip()):
        raise InvalidRoleARNError("The Role ARN format is invalid. Expected: arn:aws:iam::123456789012:role/RoleName")

def assume_role(role_arn: str) -> boto3.Session:
    sts_client = boto3.client("sts")
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AWSClarityScan",
            ExternalId="aws-clarity-scan",
            DurationSeconds=3600
        )
        credentials = response["Credentials"]
        session = boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name="us-east-1"
        )
        return session
    except ClientError as e:
        raise AssumeRoleError(f"AssumeRole failed: {str(e)}")

if __name__ == "__main__":
    import sys
    try:
        # A test dummy ARN - can be swapped with a real one
        test_arn = "arn:aws:iam::111122223333:role/AWSClarityReadOnly"
        print(f"Validating ARN format: {test_arn}")
        validate_role_arn(test_arn)
        print("✅ ARN Validated successfully.")
        
        print("\nAttempting sts:AssumeRole ...")
        session = assume_role(test_arn)
        
        identity = session.client("sts").get_caller_identity()
        print(f"✅ Successfully assumed role! Account ID: {identity['Account']}")
    except AssumeRoleError as e:
        print(f"\n❌ AWS rejected the assume_role call natively as expected with a dummy ARN:")
        print(str(e))
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error during test: {type(e).__name__} - {str(e)}")
        sys.exit(1)
