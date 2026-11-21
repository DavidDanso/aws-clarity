import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from scanner.misconfig import evaluate


class TestMisconfigEvalSmoke(unittest.TestCase):
    def test_open_ssh_security_group(self):
        resources = {
            "security_groups": [
                {
                    "id": "sg-012345",
                    "name": "web-sg",
                    "type": "security_group",
                    "status": "NOT_ASSESSED",
                    "raw": {
                        "ip_permissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            }
                        ]
                    },
                }
            ]
        }
        sg = evaluate(None, resources)["security_groups"][0]
        self.assertEqual(sg["status"], "CRITICAL")
        self.assertEqual(len(sg["issues"]), 1)
        issue = sg["issues"][0]
        self.assertEqual(issue["rule_id"], "SG-002")
        self.assertIn("Inbound SSH", issue["what_found"])
        self.assertIn("port 22", issue["what_checked"])
        self.assertEqual(issue["evidence"]["Port"], "22")
        self.assertEqual(issue["evidence"]["Source"], "0.0.0.0/0")


if __name__ == "__main__":
    unittest.main()
