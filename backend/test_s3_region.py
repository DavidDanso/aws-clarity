import unittest
from unittest.mock import MagicMock
from scanner.s3 import scan

class TestS3RegionFilter(unittest.TestCase):
    def test_s3_region_filter(self):
        # Setup mock session and s3 client
        mock_session = MagicMock()
        mock_s3 = MagicMock()
        mock_session.client.return_value = mock_s3
        
        # Mock list_buckets to return two buckets: one in us-east-1, one elsewhere
        mock_s3.list_buckets.return_value = {
            "Buckets": [
                {"Name": "bucket-us-east-1", "CreationDate": "2026-01-01T00:00:00Z"},
                {"Name": "bucket-eu-west-1", "CreationDate": "2026-01-01T00:00:00Z"}
            ]
        }
        
        # location quirk: us-east-1 returns None for LocationConstraint
        def mock_get_bucket_location(Bucket):
            if Bucket == "bucket-us-east-1":
                return {"LocationConstraint": None}
            return {"LocationConstraint": "eu-west-1"}
            
        mock_s3.get_bucket_location.side_effect = mock_get_bucket_location
        mock_s3.list_objects_v2.return_value = {"KeyCount": 1}
        
        # Run the scanner
        results = scan(mock_session)
        
        # Assertions
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "bucket-us-east-1")
        self.assertEqual(results[0]["type"], "s3_bucket")

if __name__ == '__main__':
    unittest.main()
