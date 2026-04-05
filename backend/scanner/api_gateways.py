from botocore.exceptions import ClientError
import logging

def scan(session):
    resources = []

    # REST APIs (apigateway v1)
    try:
        apigateway_client = session.client("apigateway", region_name="us-east-1")
        apis = []
        kwargs = {"limit": 500}
        while True:
            response = apigateway_client.get_rest_apis(**kwargs)
            apis.extend(response.get("items", []))
            if "position" not in response:
                break
            kwargs["position"] = response["position"]

        for api in apis:
            resources.append({
                "id": api.get("id"),
                "name": api.get("name"),
                "type": "api_gateway",
                "status": "HEALTHY",
                "issues": [],
                "raw": {
                    "created_date": api.get("createdDate"),
                    "endpoint_configuration": api.get("endpointConfiguration")
                }
            })
    except ClientError as e:
        logging.warning(f"Error scanning REST API Gateways: {e}")

    # HTTP APIs (apigatewayv2)
    try:
        apigwv2_client = session.client("apigatewayv2", region_name="us-east-1")
        apis = []
        kwargs = {}
        while True:
            response = apigwv2_client.get_apis(**kwargs)
            apis.extend(response.get("Items", []))
            if "NextToken" not in response:
                break
            kwargs["NextToken"] = response["NextToken"]

        for api in apis:
            resources.append({
                "id": api.get("ApiId"),
                "name": api.get("Name"),
                "type": "api_gateway",
                "status": "HEALTHY",
                "issues": [],
                "raw": {
                    "created_date": api.get("CreatedDate"),
                    "protocol_type": api.get("ProtocolType")
                }
            })
    except ClientError as e:
        logging.warning(f"Error scanning HTTP API Gateways: {e}")

    return resources
