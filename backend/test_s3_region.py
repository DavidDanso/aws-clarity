import os
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(__file__))
from scanner.s3 import scan


class TestS3RegionFilter(unittest.TestCase):
    def test_s3_region_filter_handles_us_east_1_and_legacy_eu(self):
        mock_session = MagicMock()
        mock_s3 = MagicMock()
        mock_session.client.return_value = mock_s3

        mock_s3.list_buckets.return_value = {
            "Buckets": [
                {"Name": "bucket-us-east-1", "CreationDate": "2026-01-01T00:00:00Z"},
                {"Name": "bucket-eu-west-1", "CreationDate": "2026-01-01T00:00:00Z"},
                {"Name": "bucket-legacy-eu", "CreationDate": "2026-01-01T00:00:00Z"},
            ]
        }

        def mock_get_bucket_location(Bucket):
            if Bucket == "bucket-us-east-1":
                return {"LocationConstraint": None}
            if Bucket == "bucket-legacy-eu":
                return {"LocationConstraint": "EU"}
            return {"LocationConstraint": "eu-west-1"}

        mock_s3.get_bucket_location.side_effect = mock_get_bucket_location
        mock_s3.list_objects_v2.return_value = {"KeyCount": 1}

        us_results = scan(mock_session, selected_regions=["us-east-1"])
        self.assertEqual(len(us_results), 1)
        self.assertEqual(us_results[0]["id"], "bucket-us-east-1")
        self.assertEqual(us_results[0]["type"], "s3_bucket")

        eu_results = scan(mock_session, selected_regions=["eu-west-1"])
        self.assertEqual({b["id"] for b in eu_results}, {"bucket-eu-west-1", "bucket-legacy-eu"})


if __name__ == "__main__":
    unittest.main()
