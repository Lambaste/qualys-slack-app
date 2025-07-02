# Qualys Slack App

This application provides integration between Qualys and Slack, allowing you to receive Qualys alerts directly in your Slack workspace via AWS Lambda.

## Features

- Receives Qualys alerts/events via AWS Lambda
- Forwards alerts to configured Slack channels using Slack Bolt
- Easily deployable with Terraform

## Requirements

- Python 3.8+
- AWS account with permissions to deploy Lambda and related resources
- Slack App credentials (Bot Token, Signing Secret)
- Terraform (for IaC deployment)

## Directory Structure

```
qualys-slack-app/
├── lambda/
│   ├── app.py                  # Lambda function source code
│   └── requirements.txt        # Python dependencies for Lambda
├── terraform/
│   ├── main.tf                 # Terraform configuration files
│   ├── variables.tf
│   ├── outputs.tf
│   └── terraform.tfvars        # (not committed if sensitive)
├── .gitignore
├── README.md
├── LICENSE
```

## Setup & Deployment

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/qualys-slack-app.git
cd qualys-slack-app
```

### 2. Prepare the Lambda Deployment Package

**Do not commit the deployment zip file to the repository.**  
Instead, build it locally as follows:

```bash
cd lambda
pip3 install -r requirements.txt -t .
zip -r app.zip .
```

This will create `app.zip` containing your Lambda function and all its dependencies.

### 3. Configure AWS Credentials

Ensure your AWS credentials are configured locally, e.g. with `aws configure`.

### 4. Set Slack Credentials

Obtain your Slack Bot Token and Signing Secret from your Slack App configuration.

You can set these as environment variables, or pass them as Terraform variables (see `terraform/variables.tf`).

### 5. Deploy with Terraform

```bash
cd terraform
terraform init
terraform apply
```

Review and approve the proposed changes. This will create the Lambda function, IAM roles, and any other required AWS resources.

### 6. Configure Slack

- Add your Lambda's API Gateway endpoint as a Request URL in your Slack App Event Subscriptions.
- Subscribe to the required Slack events (see your use case).
- Install the app to your workspace.

## Managing Dependencies

If you add new imports to `app.py`, update your dependencies:

```bash
cd lambda
pip3 freeze > requirements.txt
```

Or manually add new dependency names to `requirements.txt`.

## .gitignore

Ensure your `.gitignore` contains:

```
# Lambda deployment packages
lambda/app.zip

# Python
__pycache__/
*.pyc

# Terraform artifacts
.terraform/
terraform.tfstate
terraform.tfstate.*

# Secrets (never commit secrets)
*.env
terraform/terraform.tfvars
```

## Notes

- AWS Lambda Python runtimes include `boto3` and `botocore` by default, but you may specify versions in `requirements.txt` if you need to override.
- Only commit source code and dependency files, not built artifacts like `app.zip`.
- Always review your AWS and Slack permissions before deploying.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
