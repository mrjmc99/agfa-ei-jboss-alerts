# JBoss Check Script

## Overview

The **JBoss Check Script** is a Python script designed to monitor and report the health status of JBoss EAP (Enterprise Application Platform) instances in a cluster. The script checks the status of JBoss EAP nodes, processes log files, and sends email notifications based on certain events.

## Features

- **Cluster Node Health Check**: The script performs health checks on JBoss EAP cluster nodes to ensure their availability.

- **Log File Monitoring**: Monitors JBoss EAP log files for specific events, capturing the newest event and sending email notifications.

- **Jboss Crash Monitoring**: Monitors JBoss EAP folder for Crash Dump Files, if found, a ServiceNow ticket is generated, Email Alert is sent, and Crashdump file moved to a secondary location.

- **Email Notifications**: Sends email notifications with relevant information about the latest JBoss EAP events.

## Prerequisites

- Python 3.x installed
```bash
pip install -r requirements.txt
  ```
A user that has minimal permissions in EI, for example I created an agility user named "Monitor" and assigned it the permission set of monitoring, this is required to lookup the cluster status.
  

## Configuration

The script uses a configuration file named **jboss-check-config.ini** for various settings. Ensure that the configuration file is correctly set up before running the script.

### Configuration Parameters

- **Agfa Section:**
  - `EI_FQDN`: FQDN of the Enterprise Imaging (EI) API.
  - `EI_USER`: Username for accessing the EI API.
  - `EI_PASSWORD`: Password for accessing the EI API.
  - `log_dir`: Directory containing JBoss EAP log files.
  - `last_processed_event_file`: Path to the file storing the information about the last processed event.
  - `crashdump_logs_folder`: Path to store Jboss Crash dumps
  - `EI_jboss_path` : Path to EI Jboss

- **Email Section:**
  - `smtp_server`: SMTP server for sending email notifications.
  - `smtp_port`: SMTP server port.
  - `smtp_username`: Username for SMTP server authentication.
  - `smtp_password`: Password for SMTP server authentication.
  - `smtp_from_domain`: Domain for the 'From' address in email notifications.
  - `smtp_recipients`: Comma-separated list of email addresses to receive notifications.

- **ServiceNow Section:**
  - `api_user`: ServiceNow API Username.
  - `api_password`: ServiceNow API Password.
  - `instance`: ServiceNow Instance URL.
  - `table`: ServiceNow Table.
  - `ticket_type`: ServiceNow Ticket Type.
  - `configuration_item`: ServiceNow Configuration Item (GUID).
  - `assignment_group`: ServiceNow Assignment Group (GUID).
  - `assignee`: ServiceNow assignee (GUID).
  - `business_hours_start_time`: Business Hours Start Time.
  - `business_hours_end_time`: Business Hours End Time.
  - `after_hours_urgency`: ServiceNow After Hours Urgency.
  - `after_hours_impact`: ServiceNow After Hours Impact.
  - `business_hours_urgency`: ServiceNow Business Hours Urgency.
  - `business_hours_impact`: ServiceNow Business Hours Impact.

  
## Usage

1. Ensure that the script prerequisites are met, and the configuration file is correctly configured.

2. Test the script using Python:

   ```bash
   python jboss_check_script.py
   ```

3. Monitor the console output for information about JBoss EAP events, health checks, and email notifications.

4. Install as a scheduled task to run at server boot, script checks logs every 30 seconds by default. This script is to be installed on every Core Server in the cluster. Example: schtasks /create /ru "NT AUTHORITY\SYSTEM" /sc ONSTART /tr "'C:\Program Files\Python311\python.exe' E:\software\agfa-ei-jboss-alerts\jboss-check.py" /tn "Check Jboss Status"

## Changelog

2.14.24
 - add Jboss Crash Dump processing
   - ServiceNow Ticket creation
   - Email Alert
 - Clean up old bits of code
 - move cluster check into its own function

## Roadmap
 - Add Windows Bug Check processing



 