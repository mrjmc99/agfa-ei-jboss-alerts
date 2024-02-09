import os
import re
import time
import smtplib
import logging
import requests
import socket
from requests.exceptions import Timeout
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import configparser

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

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')



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
    except requests.RequestException as e:
        print(f"Failed to acquire token. Error: {str(e)}")
        raise

import requests

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
        raise


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

def process_newest_log_file(log_file_path, last_processed_event):
    event_pattern = re.compile(r".*?(JBoss EAP.*?(started|stopped)|Stop triggered|Timeout reached after 60s\. Calling halt|Starting JBossWS)")

    newest_event = None
    newest_event_type = None
    timestamp = None
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
            finally:
                subject = f"JBoss EAP {newest_event_type.capitalize()} on {os.environ['COMPUTERNAME']} at {local_timestamp}"
                message = f"{newest_event}\nTime: {local_timestamp}\nCluster FQDN: {EI_FQDN}\nCurrent Cluster Nodes: {cluster_nodes}"

                cluster_nodes = re.findall(r'\b\d+\.\d+\.\d+\.\d+\b', cluster_nodes)
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
                        message += f"\n{node_str} ({hostname}): {health_status}"
                    except Exception as e:
                        logging.error(f"Error processing cluster node: {e}")
                        logging.error(f"Node: {node_str}")
                        logging.error(f"IP Address: {ip_address}")
                        raise

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
          
            logging.info('Waiting for next iteration...')
            time.sleep(30)  # Adjust the interval as needed

        except Exception as e:
            logging.error(f"Error in main loop: {e}")
