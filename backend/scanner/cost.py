import os
import json
import time
from datetime import datetime, timedelta
from botocore.exceptions import ClientError


# ── /tmp cache — free, no infrastructure needed ──────────────────
# Lambda /tmp persists between warm invocations (hours to days)
# This ensures CE is called at most once per region per Lambda container lifetime

_CACHE_FILE = "/tmp/ce_cache.json"
_CACHE_TTL_SECONDS = 3600  # 1 hour — CE data only updates every 24h anyway


def _read_tmp_cache(key):
    try:
        if not os.path.exists(_CACHE_FILE):
            return None
        with open(_CACHE_FILE, "r") as f:
            store = json.load(f)
        entry = store.get(key)
        if entry and entry.get("expires_at", 0) > time.time():
            return entry["data"]
    except Exception as e:
        print(f"[cost] /tmp cache read error (non-fatal): {e}")
    return None


def _write_tmp_cache(key, data):
    try:
        store = {}
        if os.path.exists(_CACHE_FILE):
            with open(_CACHE_FILE, "r") as f:
                store = json.load(f)
        store[key] = {
            "data": data,
            "expires_at": time.time() + _CACHE_TTL_SECONDS,
        }
        # Prune expired entries to prevent /tmp growing unbounded
        now = time.time()
        store = {k: v for k, v in store.items() if v.get("expires_at", 0) > now}
        with open(_CACHE_FILE, "w") as f:
            json.dump(store, f)
    except Exception as e:
        print(f"[cost] /tmp cache write error (non-fatal): {e}")


# ── Date helpers ──────────────────────────────────────────────────

def _get_date_range():
    """
    Returns (start, end) as YYYY-MM-DD strings for current month.
    CE requires start != end — handles first-day-of-month edge case.
    """
    today = datetime.utcnow()
    start = today.replace(day=1).strftime("%Y-%m-%d")
    end = today.strftime("%Y-%m-%d")
    if start == end:
        yesterday = today - timedelta(days=1)
        start = yesterday.replace(day=1).strftime("%Y-%m-%d")
        end = yesterday.strftime("%Y-%m-%d")
    return start, end


# ── Services to exclude from user-facing cost display ─────────────
# These are AWS meta-services — showing them confuses users
# "AWS Cost Explorer" appearing in a cost tool is especially misleading

_EXCLUDED_SERVICES = {
    "AWS Cost Explorer",
    "Tax",
    "Support",
    "AWS Support (Developer)",
    "AWS Support (Business)",
    "AWS Support (Enterprise)",
}


# ── Main scan function ────────────────────────────────────────────

def scan(session, regions=None):
    """
    Fetch real month-to-date AWS costs from Cost Explorer.

    Design decisions:
    - SERVICE-level grouping only (not RESOURCE_ID — that costs extra)
    - Region-filtered query so eu-west-1 scan returns eu-west-1 costs
    - Global services (IAM, CloudFront, CE itself) always appear under
      us-east-1 in CE — included automatically via filter union
    - Results cached in /tmp for 1 hour — free, no infrastructure
    - CE data has up to 24h delay (AWS hard limitation, cannot be worked around)

    Returns:
      by_service: {service_name: amount} — filtered to scanned region(s)
      by_service_global: {service_name: amount} — global services (us-east-1)
      total_current_month: float
      period: {start, end}
      region: str — the primary region queried
      currency: "USD"
      cached: bool — True = /tmp cache hit, no CE API call made
      error: None | "PERMISSION_DENIED" | error string
    """
    if not regions:
        regions = ["us-east-1"]

    primary_region = regions[0] if len(regions) == 1 else ",".join(sorted(regions))
    start, end = _get_date_range()

    _empty = {
        "by_service": {},
        "by_service_global": {},
        "total_current_month": 0.0,
        "period": {"start": start, "end": end},
        "region": primary_region,
        "currency": "USD",
        "cached": False,
        "error": None,
    }

    # Build cache key: unique per account + region + month
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
    except Exception:
        account_id = "unknown"
    cache_key = f"ce#{account_id}#{primary_region}#{start}"

    # ── Check /tmp cache ──────────────────────────────────────────
    cached = _read_tmp_cache(cache_key)
    if cached:
        print(f"[cost] /tmp cache HIT for {primary_region} {start} — no CE API call")
        cached["cached"] = True
        return cached

    print(f"[cost] /tmp cache MISS for {primary_region} {start} — calling CE API")

    try:
        ce = session.client("ce", region_name="us-east-1")

        def _query(region_filter):
            """Run one CE GetCostAndUsage call with a region filter."""
            kwargs = {
                "TimePeriod": {"Start": start, "End": end},
                "Granularity": "MONTHLY",
                "Metrics": ["UnblendedCost"],
                "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"}],
            }
            if region_filter:
                kwargs["Filter"] = {
                    "Dimensions": {
                        "Key": "REGION",
                        "Values": region_filter,
                    }
                }
            result = {}
            response = ce.get_cost_and_usage(**kwargs)
            for time_result in response.get("ResultsByTime", []):
                for group in time_result.get("Groups", []):
                    service = group["Keys"][0]
                    amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                    if amount > 0.000001 and service not in _EXCLUDED_SERVICES:
                        result[service] = round(amount, 6)
            return result

        # Query 1: Regional costs for the scanned region(s)
        by_service = _query(regions)

        # Query 2: Global services (always stored under us-east-1 in CE)
        # Only run this second query if the scanned region is NOT us-east-1
        # to avoid double-counting
        by_service_global = {}
        if "us-east-1" not in regions:
            by_service_global = _query(["us-east-1"])
            # Keep only services not already in regional results
            # These are services that appear globally (IAM, CloudFront, etc.)
            by_service_global = {
                k: v for k, v in by_service_global.items()
                if k not in by_service
            }

        # Total = regional + global (for services unique to global)
        total = sum(by_service.values()) + sum(by_service_global.values())

        result_data = {
            "by_service": by_service,
            "by_service_global": by_service_global,
            "total_current_month": round(total, 6),
            "period": {"start": start, "end": end},
            "region": primary_region,
            "currency": "USD",
            "cached": False,
            "error": None,
        }

        _write_tmp_cache(cache_key, result_data)
        return result_data

    except ClientError as e:
        code = e.response["Error"]["Code"]
        error_key = "PERMISSION_DENIED" if code in [
            "AccessDeniedException", "OptInRequired"
        ] else str(e)
        print(f"[cost] CE API error ({code}): {e}")
        return {**_empty, "error": error_key}

    except Exception as e:
        print(f"[cost] unexpected error: {e}")
        return {**_empty, "error": str(e)}
