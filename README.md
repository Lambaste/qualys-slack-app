# qualys-slack-app

A serverless application to integrate Qualys with Slack using AWS Lambda and API Gateway.

## Overview

This project provides infrastructure and code to deploy a Slack app that interacts with Qualys APIs. It is designed to run as an AWS Lambda function, with deployment and permissions managed by Terraform. The Lambda function receives Slack events via an HTTP endpoint (API Gateway), fetches secrets from AWS Secrets Manager, and communicates with the Qualys API.

## Features

- **Serverless backend:** Built using AWS Lambda (Python 3.11)
- **Slack integration:** Exposes an endpoint for Slack events (/slack/events)
- **Qualys API integration:** Uses secrets stored in AWS Secrets Manager to authenticate with Qualys
- **Infrastructure as Code:** All AWS resources are provisioned using Terraform

## Architecture

- **AWS Lambda:** Hosts the application logic (`lambda/app.zip`)
- **API Gateway:** Provides an HTTP endpoint for Slack to send events
- **AWS Secrets Manager:** Stores Qualys and Slack credentials
- **IAM Roles & Policies:** Restricts Lambda and API Gateway permissions
- **CloudWatch:** Logs API Gateway activity

## Prerequisites

- AWS account and credentials with permission to create Lambda, API Gateway, IAM, Secrets Manager resources
- Terraform >= 1.0
- Python 3.11 (for the Lambda function code)
- Slack app and credentials (signing secret, bot token)
- Qualys API credentials

## Quickstart

1. **Clone this repository**

    ```bash
    git clone https://github.com/Lambaste/qualys-slack-app.git
    cd qualys-slack-app
    ```

2. **Configure Secrets in AWS Secrets Manager**

    - Create secrets for Qualys API and Slack app (see `terraform/terraform.tfvars` for variable names).

3. **Customize Terraform variables**

    Edit `terraform/terraform.tfvars`:

    ```hcl
    qualy_secret_name  = "your-qualys-secret-name"
    slack_secret_name  = "your-slack-secret-name"
    qualy_secret_arn   = "arn:aws:secretsmanager:...:secret:your-qualys-secret"
    slack_secret_arn   = "arn:aws:secretsmanager:...:secret:your-slack-secret"
    ```

4. **Deploy Infrastructure**

    ```bash
    cd terraform
    terraform init
    terraform apply
    ```

5. **Deploy Lambda code**

    - Ensure your Lambda function code is packaged as `lambda/app.zip`.
    - Upload or update the Lambda function as needed.

6. **Configure Slack**

    - Use the API Gateway endpoint output by Terraform to configure your Slack app's event subscription URL.

## Files & Directories

- `terraform/` – Terraform IaC for AWS resources
- `lambda/app.zip` – Python Lambda function package (not included, needs to be built)
- `README.md` – This documentation
- `LICENSE` – MIT License

## Outputs

After deployment, Terraform will output:

- `slack_api_url` – The endpoint to use in your Slack app configuration

## License

MIT License – see [LICENSE](LICENSE)
