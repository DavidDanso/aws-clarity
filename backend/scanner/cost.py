from botocore.exceptions import ClientError
from datetime import datetime, timedelta


def _get_date_range():
    """Return (start, end) for current month. Handles first-day edge case."""
    today = datetime.utcnow()
    start = today.replace(day=1).strftime("%Y-%m-%d")
    end = today.strftime("%Y-%m-%d")
    if start == end:
        # First day of month — use yesterday as end to avoid empty range
        yesterday = today - timedelta(days=1)
        start = yesterday.replace(day=1).strftime("%Y-%m-%d")
        end = yesterday.strftime("%Y-%m-%d")
    return start, end


def _query_ce(ce_client, start, end, group_by):
    """Run a Cost Explorer query. Returns ResultsByTime or raises."""
    response = ce_client.get_cost_and_usage(
        TimePeriod={"Start": start, "End": end},
        Granularity="MONTHLY",
        Metrics=["UnblendedCost"],
        GroupBy=[group_by],
    )
    return response.get("ResultsByTime", [])


def scan(session):
    """
    Fetch real AWS billing data from Cost Explorer.
    Returns:
        by_service: dict of {service_name: amount} — always populated if permission exists
        by_resource: dict of {resource_id: {amount, service}} — only if resource-level CE is enabled
        total_current_month: float
        period: {start, end}
        currency: "USD"
        resource_level_enabled: bool — tells frontend whether per-resource cost is available
        error: None | "PERMISSION_DENIED" | error string
    """
    try:
        ce = session.client("ce", region_name="us-east-1")
        start, end = _get_date_range()

        # --- Service-level costs (always available, free) ---
        by_service = {}
        total = 0.0
        for result in _query_ce(ce, start, end, {"Type": "DIMENSION", "Key": "SERVICE"}):
            for group in result.get("Groups", []):
                service = group["Keys"][0]
                amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                if amount > 0.00009:
                    by_service[service] = round(amount, 4)
                    total += amount

        # --- Resource-level costs (optional, requires CE resource-level enabled) ---
        by_resource = {}
        resource_level_enabled = False
        try:
            for result in _query_ce(ce, start, end, {"Type": "DIMENSION", "Key": "RESOURCE_ID"}):
                for group in result.get("Groups", []):
                    resource_id = group["Keys"][0]
                    amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                    if amount > 0.00009 and resource_id and resource_id != "NoResourceId":
                        by_resource[resource_id] = round(amount, 4)
            if by_resource:
                resource_level_enabled = True
        except ClientError as e:
            # DataUnavailableException means resource-level CE is not enabled — silently skip
            if e.response["Error"]["Code"] not in ["DataUnavailableException"]:
                print(f"Resource-level cost query failed: {e}")

        return {
            "by_service": by_service,
            "by_resource": by_resource,
            "total_current_month": round(total, 2),
            "period": {"start": start, "end": end},
            "currency": "USD",
            "resource_level_enabled": resource_level_enabled,
            "error": None,
        }

    except ClientError as e:
        code = e.response["Error"]["Code"]
        error_key = "PERMISSION_DENIED" if code in ["AccessDeniedException", "OptInRequired"] else str(e)
        print(f"Cost scanner failed ({code}): {e}")
        return {
            "by_service": {}, "by_resource": {},
            "total_current_month": 0.0, "period": {},
            "currency": "USD", "resource_level_enabled": False,
            "error": error_key,
        }
    except Exception as e:
        print(f"Cost scanner unexpected error: {e}")
        return {
            "by_service": {}, "by_resource": {},
            "total_current_month": 0.0, "period": {},
            "currency": "USD", "resource_level_enabled": False,
            "error": str(e),
        }
