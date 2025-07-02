import os
from slack_bolt import App
import logging
from slack_bolt.adapter.aws_lambda import SlackRequestHandler
import requests
import json
import datetime
import time
import boto3
from botocore.exceptions import ClientError
import threading
import concurrent.futures

def get_qualys_secret():

    secret_name = os.environ.get("QUALYS_SECRET_NAME", "qualys-password-here")
    region_name = "us-west-2"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        raise e

    secret_string = get_secret_value_response['SecretString']
    secret_dict = json.loads(secret_string)
    qualys_pass = secret_dict["QUALY_PASS"]
    return qualys_pass


def get_slack_secrets():
    secret_name = os.environ.get("SLACK_SECRET_NAME", "slack-app-secrets")
    region_name = "us-west-2"

    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager', region_name=region_name)

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        raise e

    secret = json.loads(get_secret_value_response['SecretString'])
    return secret["CUSTOMER_SLACK_BOT_TOKEN"], secret["CUSTOMER_SIGNING_SECRET"]



logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

CUSTOMER_SLACK_BOT_TOKEN, CUSTOMER_SIGNING_SECRET = get_slack_secrets()

# Ensure the required secrets are available
if not CUSTOMER_SLACK_BOT_TOKEN or not CUSTOMER_SIGNING_SECRET:
    raise ValueError("Missing required Slack secrets from Secrets Manager.")


app = App(process_before_response=True, # this ensures the lambda wont end prematurely while the event is still proccessing 
    token=CUSTOMER_SLACK_BOT_TOKEN,
    signing_secret=CUSTOMER_SIGNING_SECRET
)

# Event handler for app mention
@app.event("app_mention")
def hello_command(ack, body, say):
    ack()
    logger.info("Received app_mention event")
    logger.info(body) 
    message = "Hello There"
    say(message)



# Action listener for IP button click on homepage
@app.action("qualys_api_query_ip")  # This should match the action_id in the button definition
def open_modal(ack, body, client):
    ack()
    logger.info("IP button clicked")
    logger.info(body)
    trigger_id = body["trigger_id"]
    if trigger_id:
        client.views_open(
            trigger_id=trigger_id,
            view={
                "type": "modal",
                "callback_id": "qualys_api_modal_ip",
                "title": {"type": "plain_text", "text": "Enter IP Address"},
                "submit": {"type": "plain_text", "text": "Submit"},
                "blocks": [
                    {
                        "type": "input",
                        "block_id": "ip_input",
                        "label": {"type": "plain_text", "text": "IP Address"},
                        "element": {"type": "plain_text_input", "action_id": "ip_value"},
                    }
                ],
            },
        )
    else:
        logger.error("Invalid or expired trigger_id")
        
# Action listener for Hostname button click on homepage
@app.action("qualys_api_query_hostname")
def open_hostname_modal(ack, body, client):
    ack()
    logger.info("Hostname button clicked")
    logger.info(body)
    trigger_id = body["trigger_id"]
    if trigger_id:
        client.views_open(
            trigger_id=trigger_id,
            view={
                "type": "modal",
                "callback_id": "qualys_api_modal_hostname",
                "title": {"type": "plain_text", "text": "Enter Hostname"},
                "submit": {"type": "plain_text", "text": "Submit"},
                "blocks": [
                    {
                        "type": "input",
                        "block_id": "hostname_input",
                        "label": {"type": "plain_text", "text": "Hostname"},
                        "element": {"type": "plain_text_input", "action_id": "hostname_value"},
                    }
                ],
            },
        )
    else:
        logger.error("Invalid or expired trigger_id")
        

# Action listener for CVE button click on homepage
@app.action("athena_query_cve")  # This should match the action_id in the button definition
def open_modal(ack, body, client):
    ack()
    logger.info("CVE button clicked")
    logger.info(body)
    trigger_id = body["trigger_id"]
    if trigger_id:
        client.views_open(
            trigger_id=trigger_id,
            view={
                "type": "modal",
                "callback_id": "modal_query_cve",
                "title": {"type": "plain_text", "text": "Enter CVE"},
                "submit": {"type": "plain_text", "text": "Submit"},
                "blocks": [
                    {
                        "type": "input",
                        "block_id": "cve_input",
                        "label": {"type": "plain_text", "text": "CVE"},
                        "element": {"type": "plain_text_input", "action_id": "cve_value"},
                    }
                ],
            },
        )
    else:
        logger.error("Invalid or expired trigger_id")


# Action listener for vuln_host button click on homepage
@app.action("athena_query_vuln_host")  # This should match the action_id in the button definition
def open_modal(ack, body, client):
    ack()
    logger.info("vuln_host button clicked")
    logger.info(body)
    trigger_id = body["trigger_id"]
    if trigger_id:
        client.views_open(
            trigger_id=trigger_id,
            view={
                "type": "modal",
                "callback_id": "modal_query_vuln_host",
                "title": {"type": "plain_text", "text": "Enter Hostname"},
                "submit": {"type": "plain_text", "text": "Submit"},
                "blocks": [
                    {
                        "type": "input",
                        "block_id": "vuln_host_input",
                        "label": {"type": "plain_text", "text": "Input Hostname"},
                        "element": {"type": "plain_text_input", "action_id": "vuln_host_value"},
                    }
                ],
            },
        )
    else:
        logger.error("Invalid or expired trigger_id")


# Modal submission for IP address input
@app.view("qualys_api_modal_ip")
def handle_modal_submission_ip(ack, body, client):
    ack()
    logger.info("Modal IP address submission received")

    try:
        ip_address = body['view']['state']['values']['ip_input']['ip_value']['value']
        logger.info(f"IP Address received: {ip_address}")

        # Send immediate acknowledgment message to the user
        client.chat_postMessage(
            channel=body["user"]["id"],
            text=f"Your request for IP `{ip_address}` is being processed. Results will follow shortly."
        )

        # Update the modal with a loading indicator
        client.views_update(
            view_id=body["view"]["id"],
            view={
                "type": "modal",
                "callback_id": "qualys_api_modal_ip",
                "title": {"type": "plain_text", "text": "Processing..."},
                "blocks": [
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": "*Processing your request, please wait...* :hourglass_flowing_sand:"},
                    }
                ]
            }
        )
        process_qualys_submission_async(ip_address=ip_address, hostname=None, body=body, client=client)
    except Exception as e:
        logger.error(f"Error handling IP modal submission: {e}")


        
# Modal submission for hostname input
@app.view("qualys_api_modal_hostname")
def handle_modal_submission_hostname(ack, body, client):
    ack()
    logger.info("Modal hostname submission received")

    try:
        hostname = body['view']['state']['values']['hostname_input']['hostname_value']['value']
        logger.info(f"Hostname received: {hostname}")

        # Send immediate acknowledgment message to the user
        client.chat_postMessage(
            channel=body["user"]["id"],
            text=f"Your request for hostname `{hostname}` is being processed. Results will follow shortly."
        )
        
        # Update the modal with a loading indicator
        client.views_update(
            view_id=body["view"]["id"],
            view={
                "type": "modal",
                "callback_id": "qualys_api_modal_hostname",
                "title": {"type": "plain_text", "text": "Processing..."},
                "blocks": [
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": "*Processing your request, please wait...* :hourglass_flowing_sand:"},
                    }
                ]
            }
        )
        process_qualys_submission_async(ip_address=None, hostname=hostname, body=body, client=client)
    except Exception as e:
        logger.error(f"Error handling hostname modal submission: {e}")


# Modal submission for CVE input
@app.view("modal_query_cve")
def handle_modal_submission_cve(ack, body, client):
    # Acknowledge the modal submission and specify the clear action to close the modal
    ack()
    logger.info("Modal CVE submission received")
    
    try:
        cve = body['view']['state']['values']['cve_input']['cve_value']['value']
        logger.info(f"CVE received: {cve}")
        
        # Send immediate acknowledgment message to the user
        client.chat_postMessage(
            channel=body["user"]["id"],
            text=f"Counting hosts affected by `{cve}`. Results will follow shortly."
        )

        # Close the modal with a "Processing..." message
        client.views_update(
            view_id=body["view"]["id"],
            view={
                "type": "modal",
                "callback_id": "modal_query_cve",
                "title": {"type": "plain_text", "text": "Processing..."},
                "blocks": [
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": "*Processing your request, please wait...* :hourglass_flowing_sand:"},
                    }
                ]
            }
        )
        
        # Process the request asynchronously
        process_athena_submission_async(input_value=cve, input_type="cve", body=body, client=client)

    except Exception as e:
        logger.error(f"Error handling CVE modal submission: {e}")
        client.chat_postMessage(
            channel=body["user"]["id"],
            text="Something went wrong while processing your CVE request. Please try again later."
        )




# Modal submission for vuln_host input
@app.view("modal_query_vuln_host")
def handle_modal_submission_vuln_host(ack, body, client):
    ack()
    logger.info("Modal vuln_host submission received")
    
    try:
        vuln_host = body['view']['state']['values']['vuln_host_input']['vuln_host_value']['value']
        logger.info(f"vuln_host received: {vuln_host}")
        
        # Send immediate acknowledgment message to the user
        client.chat_postMessage(
            channel=body["user"]["id"],
            text=f"Your request for hostname `{vuln_host}` is being processed. Results will follow shortly."
        )
        
        # Close the modal with a "Processing..." message
        client.views_update(
            view_id=body["view"]["id"],
            view={
                "type": "modal",
                "callback_id": "modal_query_vuln_host",
                "title": {"type": "plain_text", "text": "Processing..."},
                "blocks": [
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": "*Processing your request, please wait...* :hourglass_flowing_sand:"},
                    }
                ]
            }
        )
        
        # Process the request asynchronously
        process_athena_submission_async(input_value=vuln_host, input_type="dns", body=body, client=client)

    except Exception as e:
        logger.error(f"Error handling vuln_host modal submission: {e}")
        client.chat_postMessage(
            channel=body["user"]["id"],
            text="Something went wrong while processing your request. Please try again later."
        )

        
@app.event("app_home_opened")
def update_home_tab(ack, client, event, logger):
    ack()
    try:
        client.views_publish(
            user_id=event["user"],
            view={
                "type": "home",
                "callback_id": "home_view",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"Welcome to the Qualys Slack Bot Home",
                            "emoji": True
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "Explore and query your assets and vulnerabilities with ease. Choose a section below to get started."
                        }
                    },
                    {
                        "type": "divider"
                    },
                    # Assets Section
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "Assets",
                            "emoji": True
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "Manage and inspect asset details with these options"
                        }
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "🔍 Input IP Address"
                                },
                                "action_id": "qualys_api_query_ip"
                            },
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "🔍 Input Hostname"
                                },
                                "action_id": "qualys_api_query_hostname"
                            }
                        ]
                    },
                    {
                        "type": "divider"
                    },
                    # Vulnerabilities Section
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "Vulnerabilities",
                            "emoji": True
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "Look up vulnerabilities by entering CVE details or hostname"
                        }
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "🛡️ Input CVE"
                                },
                                "action_id": "athena_query_cve"
                            },
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "🛡️ Input Hostname"
                                },
                                "action_id": "athena_query_vuln_host"
                            }
                        ]
                    },
                    {
                        "type": "divider"
                    },
                    # Dashboards Section
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "Dashboards",
                            "emoji": True
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "Get a comprehensive overview of vulnerabilities and security metrics"
                        }
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "📊 Data Center Vulnerabilities"
                                },
                                "url": "https://url-here"
                            },
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "📊 CFM Metrics"
                                },
                                "url": "https://url-here"
                            },               
                        ]
                    },
                    {
                        "type": "divider"
                    },
                    # Footer Note
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": "Need help or have questions? Reach out to the Slack channel"
                            }
                        ]
                    }
                ]
            }
        )
    except Exception as e:
        logger.error(f"Error publishing home tab: {e}")


#######################
#Athena query - optional
#######################
def handle_athena_submission(input_value, input_type, body, client):
    try:
        results = query_athena(input_value, input_type)
        if "error" in results:
            message = f"Error querying Athena: {results['error']}"
        else:
            formatted_results = format_athena_results(results)
            message = f"Results for `{input_value}`:\n```\n{formatted_results}\n```"
        client.chat_postMessage(
            channel=body["user"]["id"],
            text=message
        )
    except Exception as e:
        logger.error(f"Error in handle_athena_submission: {e}")
        client.chat_postMessage(
            channel=body["user"]["id"],
            text="Something went wrong while processing your request. Please try again later."
        )


def query_athena(search_value, search_type):
    """
    Queries AWS Athena for records matching the given search value and type.

    Args:
        search_value (str): The value to search for (DNS or CVE).
        search_type (str): The type of search to perform ('dns' or 'cve').

    Returns:
        dict: Query results.
    """
    query_string = None  # Initialize query_string outside the try block
    try:
        # Boto3 Athena client
        client = boto3.client("athena", region_name="us-west-2")

        # Construct WHERE clause
        if search_type == 'dns':
            where_clause = f"WHERE dns = '{search_value.strip()}'"
        elif search_type == 'cve':
            where_clause = f"WHERE cve_list LIKE '%{search_value.strip()}%'"
        else:
            raise ValueError("Invalid search_type. Must be 'dns' or 'cve'.")

        # Build the query string
        query_string = f"""
            SELECT title, ip, dns, cve_list, last_scan_datetime
            FROM "AwsDataCatalog"."db-name-here"."db-name-here"
            {where_clause};
        """
        logger.debug(f"Generated query: {query_string}")

        # Start the query
        response = client.start_query_execution(
            QueryString=query_string,
            QueryExecutionContext={"Database": "db-name-here"},  # Replace with your database name
            ResultConfiguration={"OutputLocation": "s3:bucket-here"},
        )
        query_execution_id = response["QueryExecutionId"]

        # Wait for the query to complete
        query_status = None
        while query_status not in ["SUCCEEDED", "FAILED", "CANCELLED"]:
            query_status_response = client.get_query_execution(QueryExecutionId=query_execution_id)
            query_status = query_status_response["QueryExecution"]["Status"]["State"]
            time.sleep(1)

        if query_status == "SUCCEEDED":
            # Fetch query results
            results = client.get_query_results(QueryExecutionId=query_execution_id)
            logger.debug(f"Query results: {results}")
            return results
        else:
            error_message = f"Query failed with status: {query_status}"
            logger.error(error_message)
            return {"error": error_message}

    except Exception as e:
        logger.error(f"Error querying Athena: {e}. Query string: {query_string}")
        return {"error": str(e)}



def format_athena_results(results, input_value, input_type, max_cve_length=50):  # Added input_type
    """
    Formats Athena query results, displaying a table for hostname queries and 
    only the count for CVE queries.

    Args:
        results (dict): The Athena query results.
        input_value (str): The value to query (hostname or CVE).
        input_type (str): The type of query ('dns' or 'cve').
        max_cve_length (int): Maximum character length for the CVE LIST column (used for truncation).

    Returns:
        str: A formatted string representing the results.
    """
    try:
        # Extract rows from Athena query results
        rows = results.get("ResultSet", {}).get("Rows", [])

        # Extract rows and format with list comprehension
        query_results = [
            {
                'title': row["Data"][0].get("VarCharValue", ""),
                'ip': row["Data"][1].get("VarCharValue", ""),
                'dns': row["Data"][2].get("VarCharValue", ""),
                'cve_list': row["Data"][3].get("VarCharValue", "").replace("[", "").replace("]", "").replace("'", "") if row["Data"][3].get("VarCharValue") else "N/A"
            }
            for row in rows[1:]
        ]

        if not query_results:
            return "No results found."

        if input_type == 'dns':  # Hostname query
            # Initialize column widths
            title_width = len('Title')
            ip_width = len('IP')
            dns_width = len('DNS')

            # Truncate CVE list and calculate column widths
            for result in query_results:
                result['cve_list'] = result['cve_list'][:max_cve_length - 3] + "..." if len(result['cve_list']) > max_cve_length else result['cve_list']
                title_width = max(title_width, len(result['title'] or 'N/A'))
                ip_width = max(ip_width, len(result['ip'] or 'N/A'))
                dns_width = max(dns_width, len(result['dns'] or 'N/A'))

            # Calculate cve_width to extend to the right edge
            total_width = title_width + ip_width + dns_width + 3 * 3 + 4  # 3 spaces between columns, 4 pipes
            cve_width = 80 - total_width  # Assuming 80 characters as the page width

            # Build the table dynamically with adjusted header widths and correct pipe placement
            header = (
                f"| {'Title'.upper().ljust(title_width)} | "
                f"{'IP'.upper().ljust(ip_width)} | "
                f"{'DNS'.upper().ljust(dns_width)} | "
                f"{'CVE List'.upper().ljust(cve_width)} \n"
                f"| {'-' * title_width} | {'-' * ip_width} | {'-' * dns_width} | {'-' * cve_width} \n"
            )

            rows_text = ""
            for result in query_results:
                cve_list = result['cve_list'].split(', ')  # Split CVEs into a list

                # First row with title, IP, and DNS
                rows_text += (
                    f"| {result['title'].ljust(title_width)} | "
                    f"{result['ip'].ljust(ip_width)} | "
                    f"{result['dns'].ljust(dns_width)} | "
                    f"{cve_list[0].ljust(cve_width) if cve_list else ' '.ljust(cve_width)} \n"
                )

                # Subsequent rows for additional CVEs
                for cve in cve_list[1:]:
                    rows_text += (
                        f"| {' '.ljust(title_width)} | "
                        f"{' '.ljust(ip_width)} | "
                        f"{' '.ljust(dns_width)} | "
                        f"{cve.ljust(cve_width - 1)} \n"  # Adjusted width to accommodate the pipe
                    )

            # Combine header and rows
            message_text = f"```\n{header}{rows_text}```"

        elif input_type == 'cve':  # CVE query
            # Count the number of hosts with the CVE
            cve_count = 0
            for result in query_results:
                cve_list = result['cve_list'].split(', ')
                if any(cve.strip() == input_value for cve in cve_list):
                    cve_count += 1

            # Return the host count
            message_text = f"```Number of hosts with {input_value}: {cve_count}```"

        else:
            message_text = "Invalid input type."

        return message_text

    except Exception as e:
        logger.error(f"Error formatting Athena results: {e}")
        return "Error formatting results."


def process_athena_submission_async(input_value, input_type, body, client):
    # Run Athena query in a separate thread
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.submit(handle_athena_submission, input_value, input_type, body, client)

def process_qualys_submission_async(ip_address=None, hostname=None, body=None, client=None):
    # Run Qualys query in a separate thread
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.submit(handle_qualys_submission, ip_address, hostname, body, client)



def handle_athena_submission(input_value, input_type, body, client):
    """
    Processes the Athena query and sends results or errors to Slack.

    Args:
        input_value (str): The value to query in Athena.
        input_type (str): The type of query (e.g., 'dns' or 'cve').
        body (dict): Slack event data.
        client: Slack WebClient for sending messages.

    Returns:
        None
    """
    try:
        # Run the Athena query
        results = query_athena(input_value, input_type)  

        # Prepare the Slack message
        user_id = body.get("user", {}).get("id")
        if not user_id:
            logger.error("User ID not found in the payload.")
            return

        if "error" in results:
            message = f"Error querying Athena: {results['error']}"
        else:
            formatted_results = format_athena_results(results, input_value, input_type)
            message = f"Results for `{input_value}`:\n{formatted_results}"

        # Send the results to Slack
        client.chat_postMessage(channel=user_id, text=message)

    except Exception as e:
        logger.error(f"Error in handle_athena_submission: {e}")
        user_id = body.get("user", {}).get("id")
        if user_id:
            client.chat_postMessage(
                channel=user_id,
                text="Something went wrong while processing your request. Please try again later."
            )


def get_jwt():
    jwt_url = "https://qualys-auth-gateway-here"
    data = {
        "username": "username",
        "password": get_qualys_secret(),
        "token": "true"
    }
    headers = {
        "ContentType": "application/x-www-form-urlencoded"
    }

    try:
        jwt_response = requests.post(jwt_url, data=data, headers=headers)
        jwt_response.raise_for_status() 
        return jwt_response
    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting JWT: {e}")
        raise


# Function to handle the submission of the IP address or hostname
# Makes a request to the Qualys API and returns the data to the user
def handle_qualys_submission(ip_address=None, hostname=None, body=None, client=None):
    Bearer = "Bearer " + get_jwt().text
    
    stripped_domain = hostname.split('.')[0] if hostname else None
    
    assetview_url = "https://qualys-base-url/am/v1/assets/host/filter/list"
    headers = {
        'X-Requested-With': "Python 3.8.0",
        'Authorization': Bearer,
        'Accept': '*/*',
        'Content-Type': 'application/json'
    }
    params_hostname = {
        "filter": f"interfaces:(hostname:'{stripped_domain}')"
    }
    params_ip = {
        "filter": f"interfaces:(address:`{ip_address}`)"
    }
    
    if ip_address:
        logger.info(f"Making Qualys API call for IP: {ip_address}")
        logger.info(f"API request parameters: {params_ip}")
        
        try:
            av_response = requests.post(assetview_url, headers=headers, params=params_ip)
            
            if av_response.status_code == 204:
                try:
                    user_id = body.get("user", {}).get("id")
                    
                    if user_id:
                        client.chat_postMessage(
                            channel=user_id,
                            text=f":information_source: Host ({ip_address}) not found in Qualys AssetView, please try again."
                        )
                    else:
                        print("User ID not found in the payload.")
                except Exception as e:
                    logger.error(f"Error: {e}")
        
            if av_response.status_code not in (200, 204):  # Check for error status codes
                logger.error(f"Qualys API call failed with status code: {av_response.status_code}")
                logger.error(f"Qualys API response text: {av_response.text}")
            else:
                logger.info(f"Qualys API response status code: {av_response.status_code}")
                logger.info(f"Qualys API response text: {av_response.text}")
                
        except Exception as e:
            logger.error(f"Error making Qualys API call for hostname: {e}")
            print(av_response.status_code)
            print(av_response)
            
    elif hostname:
        logger.info(f"Making Qualys API call for IP: {hostname}")
        logger.info(f"API request parameters: {hostname}")
        try:
            av_response = requests.post(assetview_url, headers=headers, params=params_hostname)
            
            if av_response.status_code == 204:
                try:
                    user_id = body.get("user", {}).get("id")
                    
                    if user_id:
                        client.chat_postMessage(
                            channel=user_id,
                            text=f":information_source: Host ({hostname}) not found in Qualys AssetView, please try again."
                        )
                    else:
                        print("User ID not found in the payload.")
                except Exception as e:
                    logger.error(f"Error: {e}")
                    
            if av_response.status_code not in (200, 204):  # Check for error status codes
                logger.error(f"Qualys API call failed with status code: {av_response.status_code}")
                logger.error(f"Qualys API response text: {av_response.text}")
            else:
                logger.info(f"Qualys API response status code: {av_response.status_code}")
                logger.info(f"Qualys API response text: {av_response.text}")
                
        except Exception as e:
            logger.error(f"Error making Qualys API call for hostname: {e}")
            print(av_response.status_code)
            print(av_response)
    else:
        logger.error("Neither IP address nor hostname was provided.")

    # First checking if the response was successful
    # If successful, parse the data and send it to the user
    if av_response.status_code == 200:
        try:
            # Get the user ID from the payload
            # This is used to send the message to the user who made the request
            user_id = body.get("user", {}).get("id")


            # Check if the user ID is present in the payload
            # If it is, send the message to the user
            if user_id:

                av_parsed = json.loads(av_response.text)

                message_text = ""
                
                total_hosts = len(av_parsed["assetListData"]["asset"])
                
                if total_hosts == 100:
                    total_hosts_display = "100+"
                else:
                    total_hosts_display = total_hosts

                if total_hosts > 5:
                    message_text += f"*:exclamation: Too many hosts returned: ({total_hosts_display}), please refine your query :exclamation:*\n"

                else:
                    for i, asset in enumerate(av_parsed["assetListData"]["asset"]):
                        os_name = asset["operatingSystem"]["osName"]
                        asset_name = asset["dnsName"]
                        last_scanned_date_timestamp = asset["activity"]["lastScannedDate"]
    
                        last_scanned_date_timestamp /= 1000
                        last_scanned_date = datetime.datetime.fromtimestamp(last_scanned_date_timestamp)
    
                        if 'networkInterfaceListData' in asset and 'networkInterface' in asset['networkInterfaceListData']:
                            ipv4_addresses = [interface["addressIpV4"] for interface in
                                              asset["networkInterfaceListData"]["networkInterface"] if
                                              "addressIpV4" in interface]
                        else:
                            ipv4_addresses = []
    
                        tags = [tag["tagName"] for tag in asset["tagList"]["tag"] if tag["tagName"] != "All"]
    
                        
                        message_text += "```\n"
                        message_text += (f"Operating System:\n - {os_name}\n"
                                        f"\nIP Interfaces:\n")
                        for address in ipv4_addresses:
                            message_text += f" - {address}\n"
                        message_text += (f"\nHostname:\n - {asset_name}\n"
                                        f"\nTags:\n")
                        for tag in tags:
                            message_text += f" - {tag}\n"
                        message_text += f"\nLast Scanned Date:\n - {last_scanned_date}\n"
                        message_text += "```\n"
    
                         
            if message_text:
                client.chat_postMessage(
                    channel=user_id,
                    text=message_text
                )
            else:
                print("No message to send")
        except Exception as e:
            logger.error(f"Error: {e}")
    else:
        print("Failed to make API call to Qualys URL. Status code:", av_response.status_code)
        print("Response text:", av_response.text)


# Lambda handler function for lambda invocation, entry point for lambda and will 
# be triggered whenever an event occurs. 
def lambda_handler(event, context):
    logger.info("Lambda function started")
    logger.info(f"Event: {event}") # event contains data about the request that triggered the Lambda function i.e the API gateway.
    logger.info(f"Context: {context}") # context provides runtime information about the Lambda function execution.

    try:
        slack_handler = SlackRequestHandler(app)
        response = slack_handler.handle(event, context)
        logger.info("Slack handler processed the request successfully")
        logger.info(response)
        return response
    except Exception as e:
        logger.error(f"Error processing the request: {e}")
        raise e
    finally:
        logger.info("Lambda function execution completed")
