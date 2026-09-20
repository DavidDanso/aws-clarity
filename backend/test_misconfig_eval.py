
import sys
from scanner.misconfig import evaluate, _issue

# Test resource
resources = {
    "security_groups": [
        {
            "id": "sg-012345",
            "name": "web-sg",
            "type": "security_group",
            "status": "HEALTHY",
            "raw": {
                "ip_permissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    }
                ]
            }
        }
    ]
}

res = evaluate(None, resources)
sg = res["security_groups"][0]
assert sg["status"] == "CRITICAL", "Expected CRITICAL status"
assert len(sg["issues"]) == 1, "Expected 1 issue"
issue = sg["issues"][0]
assert issue["rule_id"] == "SG-002", "Expected SG-002"
assert "what_found" in issue and "Inbound SSH" in issue["what_found"], "what_found missing or incorrect"
assert "what_checked" in issue and "port 22" in issue["what_checked"], "what_checked missing or incorrect"
assert issue["evidence"]["Port"] == "22", "evidence Port missing or incorrect"
assert issue["evidence"]["Source"] == "0.0.0.0/0", "evidence Source missing or incorrect"
print("  ✓ Python evaluate() test passed: generated explainable finding with real evidence.")
