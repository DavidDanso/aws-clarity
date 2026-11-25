import hashlib
import hmac
import re
import secrets
import threading
import boto3
import botocore.session
from botocore.config import Config
from botocore.exceptions import ClientError
from api_guard import wrap_client_with_guard
from exceptions import InvalidRoleARNError, AssumeRoleError

ROLE_ARN_PATTERN = re.compile(r"^arn:aws:iam::\d{12}:role/([\w+=,.@-]+/)*[\w+=,.@-]+$")
EXTERNAL_ID_PATTERN = re.compile(r"^[A-Za-z0-9+=,.@:/_-]{2,128}$")
DEFAULT_EXTERNAL_ID = "aws-clarity-scan"

CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CREDENTIAL_VALUE_RE = re.compile(
    r"(?i)(aws_secret_access_key|aws_session_token|SecretAccessKey|SessionToken|SecurityToken)\s*([:=])\s*([^\s,'\"\}]+)"
)
_ACCESS_KEY_ID_RE = re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")


def redact_credential_strings(text: str | None) -> str:
    """Scrub accidental AWS credential/token values before printing errors or logs."""
    if text is None:
        return ""
    cleaned = _CREDENTIAL_VALUE_RE.sub(r"\1\2[REDACTED]", str(text))
    cleaned = _ACCESS_KEY_ID_RE.sub("[REDACTED-KEY-ID]", cleaned)
    return cleaned

SCAN_BOTO_CONFIG = Config(
    connect_timeout=1.2,
    read_timeout=5,
    max_pool_connections=64,
    retries={"max_attempts": 1, "mode": "standard"},
)

_STS_CLIENT = None
_STS_LOCK = threading.Lock()

# Static botocore JSON service definitions & endpoint rules (zero credentials or tenant state).
# Reusing these across warm Lambda invocations avoids re-parsing ~10 MB of AWS API JSON specs per scan.
_SHARED_STATIC_BC = botocore.session.get_session()
_SHARED_DATA_LOADER = _SHARED_STATIC_BC.get_component("data_loader")
_SHARED_ENDPOINT_RESOLVER = _SHARED_STATIC_BC.get_component("endpoint_resolver")


def build_isolated_session(access_key_id: str, secret_access_key: str, session_token: str, region_name: str = "us-east-1") -> boto3.Session:
    """Create a tenant-isolated boto3.Session backed by the shared static AWS JSON loader."""
    bc_session = botocore.session.Session()
    bc_session.register_component("data_loader", _SHARED_DATA_LOADER)
    bc_session.register_component("endpoint_resolver", _SHARED_ENDPOINT_RESOLVER)
    return boto3.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token,
        region_name=region_name,
        botocore_session=bc_session,
    )


def _get_sts_client():
    global _STS_CLIENT
    if _STS_CLIENT is None:
        with _STS_LOCK:
            if _STS_CLIENT is None:
                _STS_CLIENT = boto3.client("sts", region_name="us-east-1", config=SCAN_BOTO_CONFIG)
    return _STS_CLIENT


class CachedSession:
    """Thread-safe boto3.Session wrapper that caches clients by (service, region)
    and enforces fast connect/read timeouts on every scanner call.

    Uses per-service locks (instead of one global lock) so regional clients for
    ec2, lambda, rds, dynamodb, cloudwatch, logs, and cloudtrail construct
    concurrently without contending on a single mutex.
    """

    def __init__(
        self,
        session: boto3.Session,
        config: Config = SCAN_BOTO_CONFIG,
        enforce_api_allowlist: bool = False,
        include_s3: bool = True,
    ):
        self._session = session
        self._config = config
        self._enforce_api_allowlist = enforce_api_allowlist
        self._include_s3 = include_s3
        self._locks_guard = threading.Lock()
        self._service_locks: dict[str, threading.Lock] = {}
        self._clients: dict[tuple[str, str | None], object] = {}

    def _maybe_guard(self, client, service_name: str):
        if not self._enforce_api_allowlist:
            return client
        return wrap_client_with_guard(client, service_name, include_s3=self._include_s3)

    def _get_service_lock(self, service_name: str) -> threading.Lock:
        lock = self._service_locks.get(service_name)
        if lock is not None:
            return lock
        with self._locks_guard:
            lock = self._service_locks.get(service_name)
            if lock is None:
                lock = threading.Lock()
                self._service_locks[service_name] = lock
            return lock

    def client(self, service_name: str, region_name: str | None = None, config: Config | None = None, **kwargs):
        if kwargs:
            raw = self._session.client(
                service_name,
                region_name=region_name,
                config=config or self._config,
                **kwargs,
            )
            return self._maybe_guard(raw, service_name)
        key = (service_name, region_name)
        cached = self._clients.get(key)
        if cached is not None:
            return cached
        with self._get_service_lock(service_name):
            cached = self._clients.get(key)
            if cached is None:
                raw = self._session.client(
                    service_name,
                    region_name=region_name,
                    config=config or self._config,
                )
                cached = self._maybe_guard(raw, service_name)
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
    sts_client = _get_sts_client()
    try:
        response = sts_client.assume_role(
            RoleArn=resolved_arn,
            RoleSessionName="AWSClarityScan",
            ExternalId=resolved_external_id,
            DurationSeconds=3600,
        )
        credentials = response["Credentials"]
        session = build_isolated_session(
            access_key_id=credentials["AccessKeyId"],
            secret_access_key=credentials["SecretAccessKey"],
            session_token=credentials["SessionToken"],
            region_name="us-east-1",
        )
        # Attach verified identity & temporary STS credentials for in-memory map-reduce sub-workers
        session._aws_clarity_account_id = resolved_arn.split(":")[4]
        session._aws_clarity_caller_arn = (response.get("AssumedRoleUser") or {}).get("Arn", "")
        session._aws_clarity_credentials = {
            "AccessKeyId": credentials["AccessKeyId"],
            "SecretAccessKey": credentials["SecretAccessKey"],
            "SessionToken": credentials["SessionToken"],
        }
        return session
    except ClientError as e:
        raise AssumeRoleError(f"AssumeRole failed: {str(e)}") from e
