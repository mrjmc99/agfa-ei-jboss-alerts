import os
import re
import shutil
import time
import smtplib
import logging
import requests
import socket
import uuid
from requests.exceptions import Timeout
from datetime import datetime, timedelta
from email.mime.text import MIMEText
import configparser

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Get the absolute path of the script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Construct the absolute path of the configuration file
config_file_path = os.path.join(script_dir, "jboss-check-config.ini")

# Load the configuration file
config = configparser.ConfigParser()
config.read(config_file_path)

#EI API Variables
EI_FQDN = config.get("Agfa", "EI_FQDN")
EI_USER = config.get("Agfa", "EI_USER")
EI_PASSWORD = config.get("Agfa", "EI_PASSWORD")
log_dir = config.get("Agfa", "log_dir")
EI_jboss_path = config.get("Agfa", "EI_jboss_path")
crashdump_logs_folder = config.get("Agfa", "crashdump_logs_folder")
# Construct the absolute path of the last_processed_event_file
last_processed_event_file = os.path.join(script_dir, config.get("Agfa", "last_processed_event_file"))
TOKEN = None

#email variables
smtp_server = config.get("Email", "smtp_server")
smtp_port = config.get("Email", "smtp_port")
smtp_username = config.get("Email", "smtp_username")
smtp_password = config.get("Email", "smtp_password")
smtp_from_domain = config.get("Email", "smtp_from_domain")
smtp_from = f"{os.environ['COMPUTERNAME']}@{smtp_from_domain}"
smtp_recipients_string = config.get("Email", "smtp_recipients")
smtp_recipients = smtp_recipients_string.split(",")

#service now variables
service_now_instance = config.get("ServiceNow", "instance")
service_now_table = config.get("ServiceNow", "table")
service_now_api_user = config.get("ServiceNow", "api_user")
service_now_api_password = config.get("ServiceNow", "api_password")
ticket_type = config.get("ServiceNow", "ticket_type")
configuration_item = config.get("ServiceNow", "configuration_item")
assignment_group = config.get("ServiceNow", "assignment_group")
assignee = config.get("ServiceNow", "assignee")
business_hours_start_time = config.get("ServiceNow", "business_hours_start_time")
business_hours_end_time = config.get("ServiceNow", "business_hours_end_time")
after_hours_urgency = config.get("ServiceNow", "after_hours_urgency")
after_hours_impact = config.get("ServiceNow", "after_hours_impact")
business_hours_urgency = config.get("ServiceNow", "business_hours_urgency")
business_hours_impact = config.get("ServiceNow", "business_hours_impact")



# Get the current time and day of the week
current_time = datetime.now().time()
current_day = datetime.now().weekday()

# Define business hours
business_hours_start = datetime.strptime(business_hours_start_time, "%H:%M:%S").time()
business_hours_end = datetime.strptime(business_hours_end_time, "%H:%M:%S").time()

# Set default values
urgency = after_hours_urgency  # Default value for after hours and weekends
impact = after_hours_urgency   # Default value for after hours and weekends

# Check if it's business hours
if business_hours_start <= current_time <= business_hours_end and current_day < 5:  # Monday to Friday
    urgency = business_hours_urgency
    impact = business_hours_impact


#function to get auth token
def get_token():
    global TOKEN
    print(f"Getting a token for user {EI_USER}")
    auth_url = f"https://{EI_FQDN}/authentication/token"
    params = {"user": EI_USER, "password": EI_PASSWORD}

    try:
        response = requests.get(auth_url, params=params, verify=True)
        response.raise_for_status()
        TOKEN = response.text.split('CDATA[')[1].split(']]')[0]
        print("Token acquired successfully.")
        return True  # Indicate successful token acquisition
    except requests.HTTPError as e:
        if e.response.status_code == 403:
            print("Token acquisition failed: HTTP 403 Forbidden. Check credentials or permissions.")
        else:
            print(f"Failed to acquire token. Error: {str(e)}")
        return False  # Indicate failed token acquisition
    except requests.RequestException as e:
        print(f"Failed to acquire token. Error: {str(e)}")
        return False  # Indicate failed token acquisition


#function to release token
def release_token():
    print(f"Releasing token for user: {EI_USER}")
    auth_url = f"https://{EI_FQDN}/authentication/logout"
    headers = {"Authorization": f"Bearer {TOKEN}"}

    try:
        response = requests.get(auth_url, headers=headers, verify=True)
        response.raise_for_status()
        print("Token released successfully.")
        return True  # Indicate successful token release
    except requests.RequestException as e:
        print(f"Failed to release token. Error: {str(e)}")
        return False  # Indicate failed token release



def check_cluster_node_health(ip_address):
    health_url = f"http://{ip_address}/status"

    try:
        response = requests.get(health_url, timeout=2)  # Set the timeout to 2 seconds
        response.raise_for_status()
        health_status = response.text.strip()
        print(f"Node {ip_address}: {response.status_code} - {response.text.strip()}")
        return health_status
    except Timeout:
        health_status = "Unavailable: (Starting or Stopping)"
        print(f"Node {ip_address}: Timeout")
    except requests.RequestException as e:
        health_status = f"Unavailable: (Starting or Stopping) {str(e)}"
        print(f"Node {ip_address}: Error - {str(e)}")

    return health_status


def call_cluster_api():
    print("Calling EI API")
    token_acquired = get_token()

    if not token_acquired:
        print("Unable to acquire token. Skipping API call.")
        return "Unable to look up Cluster"

    headers = {"Authorization": f"Bearer {TOKEN}", "Accept": "application/json"}
    cluster_url = f"https://{EI_FQDN}/ris/web/v2/queues/availableNodes"

    try:
        response = requests.get(cluster_url, headers=headers, verify=True)
        response.raise_for_status()
        print("API call successful.")
        print(response.text)
        return response.text
    except requests.RequestException as e:
        print(f"API call failed. Error: {str(e)}")
        return "Unable to look up Cluster"
    finally:
        release_token()



def save_last_processed_event(last_processed_event, file_path):
    with open(file_path, 'w') as file:
        file.write(str(last_processed_event))


def load_last_processed_event(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.read().strip()
    except FileNotFoundError:
        return None


def send_email( subject, message):
    msg = MIMEText(message)
    msg["From"] = smtp_from
    msg["To"] = ", ".join(smtp_recipients)  # Join smtp_recipients with a comma and space
    msg["Subject"] = subject

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.sendmail(smtp_from, smtp_recipients, msg.as_string())
        server.quit()
        print(f"Email sent to {', '.join(smtp_recipients)}")
    except Exception as e:
        print(f"Email sending failed to {', '.join(smtp_recipients)}: {e}")

    except Exception as e:
        logging.error(f"Error sending email: {e}")

# Process Core Dump
def process_core_dump(crashdump_file):
    crashdump_source_path = os.path.join(EI_jboss_path, crashdump_file)
    crashdump_log_file_name = os.path.splitext(crashdump_file)[0] + '.log'
    crashdump_log_source_path = os.path.join(log_dir, crashdump_log_file_name)
    destination_path = crashdump_logs_folder
    os.makedirs(destination_path, exist_ok=True)
    external_unique_id = str(uuid.uuid4())
    cluster_nodes = None

    try:
        # get timestamp of crash
        crash_timestamp_seconds = os.path.getmtime(crashdump_source_path)

        # Convert timestamp to local time
        dt_format = "%Y/%m/%d %H:%M:%S.%f"
        utc_dt = datetime.utcfromtimestamp(crash_timestamp_seconds)
        offset_minutes = int((datetime.utcnow() - datetime.now()).total_seconds() / 60)
        local_dt = utc_dt - timedelta(minutes=offset_minutes)
        crash_timestamp = local_dt.strftime(dt_format)

        # move crash dump out of bin folder to crash dump logs folder
        logging.info(f"Moving crash dump file from {crashdump_source_path} to {destination_path}")
        shutil.move(crashdump_source_path, destination_path)

        # copy matching crashdump logfile to crash dump logs folder
        logging.info(f"Copying crash dump log file from {crashdump_log_source_path} to {destination_path}")
        shutil.copy(crashdump_log_source_path, destination_path)

        # setup email variables
        subject = f"JBoss EAP Crashed on {os.environ['COMPUTERNAME']} at {crash_timestamp}"
        message = f"JBoss EAP Crashed\nTime: {crash_timestamp}\nCluster FQDN: {EI_FQDN}\n"

        # Check cluster health
        cluster_nodes = call_cluster_api()
        # Check cluster nodes
        if cluster_nodes:
            message += f"\nCurrent Cluster Nodes: {cluster_nodes}"
            message = check_cluster_nodes(cluster_nodes, message)
        else:
            message += f"\nFailed to retrieve cluster nodes information."

        # Create ServiceNow incident and get the incident number
        incident_number, sys_id = create_service_now_incident(
            subject, message,
            configuration_item, external_unique_id,
            urgency, impact, ticket_type
        )

        # Attach the Log file to the ServiceNow incident
        if incident_number and sys_id:
            logging.info(f"Attaching crash dump log file to incident: {crashdump_log_source_path}")
            attach_file_to_incident(sys_id, crashdump_log_source_path)
            subject += f" Ticket: {incident_number}"

        # send email
        send_email(subject, message)

        # Log information
        logging.info(f"Processed core dump: {crashdump_file}, Zip file: {crashdump_log_source_path} Ticket: {incident_number}")

    except Exception as e:
        logging.error(f"Error processing core dump: {e}")




def attach_file_to_incident(incident_number, file_path):
    attachment_api_url = f"https://{service_now_instance}/api/now/attachment/upload"

    headers = {
        "Accept": "application/json",
    }

    data = {
        "table_name": service_now_table,
        "table_sys_id": incident_number,
    }

    files = {
        'file': (os.path.basename(file_path), open(file_path, 'rb')),
    }

    try:
        print("Sending attachment request...")
        print("Data:", data)
        print("Files:", files)
        attachment_response = requests.post(
            attachment_api_url,
            headers=headers,
            auth=(service_now_api_user, service_now_api_password),
            data=data,
            files=files,
        )

        print("Attachment response status code:", attachment_response.status_code)
        print("Attachment response text:", attachment_response.text)

        if attachment_response.status_code == 201:
            print("File attached to ServiceNow incident successfully")
        else:
            print(f"Failed to attach file to ServiceNow incident. Response: {attachment_response.text}")

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while attaching the file to ServiceNow incident: {e}")


# function to resolve and check cluster nodes
def check_cluster_nodes(cluster_nodes, message):
    cluster_nodes = re.findall(r'\b\d+\.\d+\.\d+\.\d+\b', cluster_nodes)
    new_message = message  # Create a new string based on the existing message

    for node in cluster_nodes:
        try:
            node_str = str(node)
            print(f"Processing cluster node: {node_str}")

            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', node_str)
            ip_address = ip_match.group() if ip_match else "Unknown"

            # Perform hostname lookup
            try:
                hostname, _, _ = socket.gethostbyaddr(ip_address)
                # Strip the domain part from the hostname
                if '.' in hostname:
                    hostname = hostname.split('.')[0]
            except (socket.herror, socket.gaierror):
                hostname = "Unknown"

            print(f"Extracted IP address: {ip_address}, Hostname: {hostname}")

            health_status = check_cluster_node_health(ip_address)
            new_message += f"\n{node_str} ({hostname}): {health_status}"
        except Exception as e:
            logging.error(f"Error processing cluster node: {e}")
            logging.error(f"Node: {node_str}")
            logging.error(f"IP Address: {ip_address}")
            raise

    return new_message  # Return the new string


# Function to create service now tickets
def create_service_now_incident(summary, description, configuration_item, external_unique_id, urgency, impact, ticket_type):
    incident_api_url = f"https://{service_now_instance}/api/now/table/{service_now_table}"

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    payload = {
        "u_short_description": summary,
        "u_description": description,
        #"u_affected_user_id": affected_user_id,
        "u_configuration_item": configuration_item,
        "u_external_unique_id": external_unique_id,
        "u_urgency": urgency,
        "u_impact": impact,
        "u_type": ticket_type,
        "u_assignment_group": assignment_group,
    }

    try:
        print("Incident Creation Payload:", payload)  # Print payload for debugging
        response = requests.post(
            incident_api_url,
            headers=headers,
            auth=(service_now_api_user, service_now_api_password),
            json=payload,
        )

        print("Incident Creation Response Status Code:", response.status_code)  # Print status code for debugging
        print("Incident Creation Response Content:", response.text)  # Print response content for debugging

        if response.status_code == 201:
            incident_number = response.json().get("result", {}).get("u_task_string")
            sys_id = response.json().get('result', {}).get('u_task', {}).get('value')
            print(f"ServiceNow incident created successfully: {incident_number} {sys_id}")
            return incident_number, sys_id
        else:
            print(f"Failed to create ServiceNow incident. Response: {response.text}")

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while creating ServiceNow incident: {e}")

    return None, None

def process_newest_log_file(log_file_path, last_processed_event):
    event_pattern = re.compile(r".*?(JBoss EAP.*?(started|stopped)|Stop triggered|Timeout reached after 60s\. Calling halt|Starting JBossWS)")
    cluster_nodes = None
    newest_event = None
    newest_event_type = None
    local_timestamp = None

    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            for i in reversed(range(len(lines))):
                line = lines[i]
                match = event_pattern.search(line)
                if match:
                    newest_event = line.strip()
                    newest_event_type = match.group(2) or match.group(1)
                    logging.info(f"Found event: {newest_event}, type: {newest_event_type}")

                    timestamp_line = lines[i - 1]
                    time_start = timestamp_line.find('time="') + 6
                    time_end = timestamp_line.find('"', time_start)
                    if time_start != -1 and time_end != -1:
                        timestamp = timestamp_line[time_start:time_end]

                        # Convert timestamp to local time
                        dt_format = "%Y/%m/%d %H:%M:%S.%f"
                        utc_dt = datetime.strptime(timestamp[:-6], dt_format)
                        offset_minutes = int((datetime.utcnow() - datetime.now()).total_seconds() / 60)
                        local_dt = utc_dt - timedelta(minutes=offset_minutes)
                        local_timestamp = local_dt.strftime(dt_format)

                        # Format the local time
                        local_timestamp = local_dt.strftime("%H:%M:%S %m/%d/%y")

                        break

        if newest_event and newest_event != last_processed_event:
            try:
                get_token()
                cluster_nodes = call_cluster_api()
                release_token()
            finally:
                subject = f"JBoss EAP {newest_event_type.capitalize()} on {os.environ['COMPUTERNAME']} at {local_timestamp}"
                message = f"{newest_event}\nTime: {local_timestamp}\nCluster FQDN: {EI_FQDN}\n"
                # Check cluster nodes
                if cluster_nodes:
                    message += f"\nCurrent Cluster Nodes: {cluster_nodes}"
                    message = check_cluster_nodes(cluster_nodes, message)
                else:
                    message = f"\nFailed to retrieve cluster nodes information."
                #send alert email
                send_email(subject, message)
                return newest_event
    except Exception as e:
        logging.error(f"Error processing log file: {e}")

    return last_processed_event









if __name__ == '__main__':
    last_processed_event = load_last_processed_event(last_processed_event_file)

    while True:
        try:
            logging.info('Processing log files...')
            log_files = sorted(
                (f for f in os.listdir(log_dir) if f.startswith('server-') and f.endswith('.log')),
                reverse=True
            )
            if log_files:
                newest_log_file = log_files[0]
                log_file_path = os.path.join(log_dir, newest_log_file)
                logging.info(f'Processing the newest log file: {log_file_path}')
                last_processed_event = process_newest_log_file(log_file_path, last_processed_event)
                
                # Save the last_processed_event to the file
                save_last_processed_event(last_processed_event, last_processed_event_file)
            crashdump = list(f for f in os.listdir(EI_jboss_path) if f.endswith('.mdmp'))
            if crashdump:
                crashdump_file = crashdump[0]
                logging.info(f'Processing crashdump: {crashdump_file}')
                process_core_dump(crashdump_file)

          
            logging.info('Waiting for next iteration...')
            time.sleep(30)  # Adjust the interval as needed

        except Exception as e:
            logging.error(f"Error in main loop: {e}")