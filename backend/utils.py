import re
import boto3
from botocore.exceptions import ClientError
from exceptions import InvalidRoleARNError, AssumeRoleError

ROLE_ARN_PATTERN = re.compile(r"^arn:aws:iam::\d{12}:role/([\w+=,.@-]+/)*[\w+=,.@-]+$")
EXTERNAL_ID_PATTERN = re.compile(r"^[A-Za-z0-9+=,.@:/_-]{2,128}$")
DEFAULT_EXTERNAL_ID = "aws-clarity-scan"


def validate_role_arn(role_arn: str) -> str:
    if not isinstance(role_arn, str) or not ROLE_ARN_PATTERN.match(role_arn.strip()):
        raise InvalidRoleARNError(
            "The Role ARN format is invalid. Expected: arn:aws:iam::123456789012:role/RoleName"
        )
    return role_arn.strip()


def validate_external_id(external_id: str | None) -> str:
    if external_id is None or str(external_id).strip() == "":
        return DEFAULT_EXTERNAL_ID
    cleaned = str(external_id).strip()
    if not EXTERNAL_ID_PATTERN.match(cleaned):
        raise InvalidRoleARNError(
            "Invalid External ID format. Use 2-128 alphanumeric or +=,.@:/_- characters."
        )
    return cleaned


def assume_role(role_arn: str, external_id: str | None = None) -> boto3.Session:
    resolved_arn = validate_role_arn(role_arn)
    resolved_external_id = validate_external_id(external_id)
    sts_client = boto3.client("sts")
    try:
        response = sts_client.assume_role(
            RoleArn=resolved_arn,
            RoleSessionName="AWSClarityScan",
            ExternalId=resolved_external_id,
            DurationSeconds=3600,
        )
        credentials = response["Credentials"]
        return boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name="us-east-1",
        )
    except ClientError as e:
        raise AssumeRoleError(f"AssumeRole failed: {str(e)}") from e
