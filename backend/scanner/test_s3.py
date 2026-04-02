import unittest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError
import s3

class TestS3Scanner(unittest.TestCase):

    def test_s3_us_east_1_location_quirk(self):
        # Setup mock session and client
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client
        
        # We will return 2 buckets, one in us-east-1 (None location) and one in us-west-2
        mock_s3_client.list_buckets.return_value = {
            "Buckets": [
                {"Name": "bucket-us-east-1", "CreationDate": "2026-04-01T00:00:00Z"},
                {"Name": "bucket-us-west-2", "CreationDate": "2026-04-01T00:00:00Z"}
            ]
        }
        
        # Side effect for get_bucket_location
        def mock_get_bucket_location(Bucket):
            if Bucket == "bucket-us-east-1":
                return {"LocationConstraint": None}
            else:
                return {"LocationConstraint": "us-west-2"}
                
        mock_s3_client.get_bucket_location.side_effect = mock_get_bucket_location
        
        # Empty objects for simplicity
        mock_s3_client.list_objects_v2.return_value = {"KeyCount": 0}

        # Run scanner
        resources = s3.scan(mock_session)
        
        # Verify only the us-east-1 bucket was returned
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0]["name"], "bucket-us-east-1")
        self.assertEqual(resources[0]["raw"]["location"], None)

if __name__ == "__main__":
    unittest.main()
