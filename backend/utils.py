import hashlib
import hmac
import re
import secrets
import threading
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from exceptions import InvalidRoleARNError, AssumeRoleError

ROLE_ARN_PATTERN = re.compile(r"^arn:aws:iam::\d{12}:role/([\w+=,.@-]+/)*[\w+=,.@-]+$")
EXTERNAL_ID_PATTERN = re.compile(r"^[A-Za-z0-9+=,.@:/_-]{2,128}$")
DEFAULT_EXTERNAL_ID = "aws-clarity-scan"

CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

SCAN_BOTO_CONFIG = Config(
    connect_timeout=3,
    read_timeout=8,
    max_pool_connections=32,
    retries={"max_attempts": 2, "mode": "standard"},
)


class CachedSession:
    """Thread-safe boto3.Session wrapper that caches clients by (service, region)
    and enforces fast connect/read timeouts on every scanner call.

    Prevents constructing duplicate heavy botocore clients (e.g. EC2 built 8x per
    region across 30+ regions) and avoids non-thread-safe client initialization.
    """

    def __init__(self, session: boto3.Session, config: Config = SCAN_BOTO_CONFIG):
        self._session = session
        self._config = config
        self._lock = threading.Lock()
        self._clients: dict[tuple[str, str | None], object] = {}

    def client(self, service_name: str, region_name: str | None = None, config: Config | None = None, **kwargs):
        if kwargs:
            return self._session.client(
                service_name,
                region_name=region_name,
                config=config or self._config,
                **kwargs,
            )
        key = (service_name, region_name)
        cached = self._clients.get(key)
        if cached is not None:
            return cached
        with self._lock:
            cached = self._clients.get(key)
            if cached is None:
                cached = self._session.client(
                    service_name,
                    region_name=region_name,
                    config=config or self._config,
                )
                self._clients[key] = cached
            return cached


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


def generate_scan_token() -> tuple[str, str]:
    """Generate a 256-bit ephemeral scan access token and its SHA-256 hex digest."""
    token = secrets.token_urlsafe(32)
    return token, hash_scan_token(token)


def hash_scan_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_scan_token(provided_token: str | None, expected_hash: str | None) -> bool:
    if not provided_token or not expected_hash:
        return False
    computed = hash_scan_token(provided_token.strip())
    return hmac.compare_digest(computed, expected_hash)


def sanitize_metadata_text(value: str | None, max_length: int = 256) -> str:
    """Strip control characters and bound length for untrusted AWS resource metadata."""
    if value is None:
        return ""
    cleaned = CONTROL_CHARS_RE.sub("", str(value)).strip()
    if len(cleaned) > max_length:
        return cleaned[: max_length - 1] + "…"
    return cleaned


def assume_role(role_arn: str, external_id: str | None = None) -> boto3.Session:
    resolved_arn = validate_role_arn(role_arn)
    resolved_external_id = validate_external_id(external_id)
    sts_client = boto3.client("sts", config=SCAN_BOTO_CONFIG)
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
