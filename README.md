# AWS Clarity

AWS Clarity is a serverless, read-only AWS resource scanner that provides a clear overview of the security state of an AWS account. It evaluates common resources like S3, EC2, RDS, IAM, and Security Groups for misconfigurations and orphaned resources.

## Deployment Instructions

### Prerequisites
- AWS CLI configured with appropriate permissions.
- Terraform installed and initialized in the `infra` directory.
- Node.js installed to build the frontend.

### Frontend Deployment Steps

To deploy the frontend to the S3 bucket and serve it via CloudFront, follow these steps:

1. **Build the Application**
   Navigate to the `frontend` directory and create a production build:
   ```bash
   cd frontend
   npm install
   npm run build
   ```

2. **Sync to S3**
   Upload the compiled application artifacts to your provisioning S3 bucket. Ensure you fetch the bucket name from Terraform outputs (`terraform output s3_bucket_name` in the `infra` directory):
   ```bash
   aws s3 sync dist/ s3://<your-s3-bucket-name>/ --delete
   ```

3. **Invalidate CloudFront Cache**
   To ensure users receive the latest deployed version immediately, invalidate the CloudFront cache. Get your distribution ID from Terraform outputs or the AWS Console:
   ```bash
   aws cloudfront create-invalidation --distribution-id <your-cloudfront-id> --paths "/*"
   ```

4. **Verify Application**
   Open the CloudFront URL (`terraform output cloudfront_url`) in your browser to verify the setup screen is available over HTTPS. Try launching a scan using an AWS Role ARN configured with `sts:AssumeRole`.
