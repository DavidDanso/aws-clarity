import concurrent.futures
from botocore.exceptions import ClientError
from exceptions import ScannerError


def _inspect_table(client, name, region):
    assessment_errors = {}
    try:
        table_info = client.describe_table(TableName=name).get("Table", {})
        # AWS encrypts all DynamoDB tables at rest by default using an AWS-owned key.
        # When AWS-owned encryption is active, AWS omits SSEDescription entirely.
        raw_sse = table_info.get("SSEDescription")
        if raw_sse:
            sse_desc = raw_sse
        else:
            sse_desc = {"Status": "ENABLED", "SSEType": "AWS_OWNED"}

        billing_summary = table_info.get("BillingModeSummary") or {}
        billing_mode = billing_summary.get("BillingMode", "PROVISIONED")
        provisioned = table_info.get("ProvisionedThroughput") or {}

        raw = {
            "table_arn": table_info.get("TableArn"),
            "table_status": table_info.get("TableStatus"),
            "billing_mode": billing_mode,
            "read_capacity_units": provisioned.get("ReadCapacityUnits"),
            "write_capacity_units": provisioned.get("WriteCapacityUnits"),
            "item_count": table_info.get("ItemCount"),
            "table_size_bytes": table_info.get("TableSizeBytes"),
            "creation_date_time": table_info.get("CreationDateTime"),
            "sse_description": sse_desc,
        }
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "AWS error")
        raw = {}
        assessment_errors["DDB-001"] = f"Could not describe table: {code}"
        assessment_errors["DDB-002"] = f"Could not describe table: {code}"

    item = {
        "id": name,
        "name": name,
        "type": "dynamodb_table",
        "service": "DynamoDB",
        "status": "INCOMPLETE",
        "issues": [],
        "region": region,
        "raw": raw,
    }
    if assessment_errors:
        item["assessment_errors"] = assessment_errors
    return item


def scan(session, region="us-east-1"):
    resources = []
    try:
        client = session.client("dynamodb", region_name=region)
        tables = []
        kwargs = {}
        while True:
            response = client.list_tables(**kwargs)
            tables.extend(response.get("TableNames", []))
            if "LastEvaluatedTableName" not in response:
                break
            kwargs["ExclusiveStartTableName"] = response["LastEvaluatedTableName"]
    except ClientError as e:
        raise ScannerError(str(e), resources) from e

    if not tables:
        return resources

    if len(tables) == 1:
        return [_inspect_table(client, tables[0], region)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, len(tables))) as ex:
        return list(ex.map(lambda name: _inspect_table(client, name, region), tables))
