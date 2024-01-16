import os
# Import the EmailClient class from the Azure Communication Services for email Notifications
from azure.communication.email import EmailClient
import base64
import json
import logging
import functions_framework

@functions_framework.cloud_event
def scc_notification_handler(event, context):
    """Cloud Function to be triggered by PubSub subscription.
       This function receives messages containing SCC Findings data. 
       It creates a log entry within the project allowing Cloud 
       Monitoring to be used for alerting on the SCC findings.

    Args:
        event (dict): The PubSub message payload.
        context (google.cloud.functions.Context): Metadata of triggering event.
    Returns:
        None; the output is written to Cloud Logging.
    """
    # Get the Pub/Sub as messages come in encrypted form
    # pubsub_message = base64.b64decode(event['data']).decode('utf-8')
    print("This cloud function was triggered by messageId {} published at {}.".format(context.event_id, context.timestamp))

    try:
        # PubSub messages come in encrypted
        pubsubMessage = base64.b64decode(event['data']).decode('utf-8')
        
        print(f'validating if SCC data is loading: {pubsubMessage}')
        logging.info(f'validating if SCC data is loading: {pubsubMessage}')

        # Parse SCC finding from the Pub/Sub message
        message_json = json.loads(pubsubMessage)
        
        send_email_message(message_json)
    except Exception as e:
        pubsubMessage = "error decoding payload"



# def send_email_message(finding):
#     try:
#         vendorName = finding.get("Severity", "Unknown Vendor")
#         severity = finding.get("Severity", "Unknown Severity")

# poller = email_client.begin_send(message)
# result = poller.result()


def send_email_message(finding):
    try:
        # connection_string = connectionString
        connection_string = ""
        client = EmailClient.from_connection_string(connection_string)

        #################################### 
        # From Finding Incoming Json Object
        ####################################
        severity = finding.get('finding',{}).get('severity', 'Not defined')
        # severity = finding['finding']['severity']
        # severity = finding('Severity','Unknown Severity')

        findingType = finding.get('finding',{}).get('findingClass') #Threat,Vulnerability,Misconfiguration,Observation,SCC Error,Finding class unspecified
        # findingType = finding['finding']['findingClass']

        state = finding.get('finding', {}).get('state', 'Unknown State' ) #ACTIVE, NOT ACTIVE
        # state = finding['finding']['state']

        findingfromComponent = finding['finding']['parentDisplayName'] # Provides the subcomponent of SCC, for eg ETD(Event Threat Detection)

        findingname = finding.get('finding', {}).get('category', 'Unknow Category') # Provides summary heading of the finding 

        description = finding.get('finding', {}).get('description', 'No description available') # Provides description of the finding

        url = finding.get('finding', {}).get('externalUri', 'No url provided') # Provides link to SCC Finding page

        #################################### 
        # From Resource Incoming Json Object
        ####################################
        projectDisplayName = finding.get('resource', {}).get('projectDisplayName', 'No Project defined') # Provides the details of project/org

        ############################################
        # From sourceProperties Incoming Json Object
        ############################################
        instructions = finding.get('sourceProperties', {}).get('Recommendation', 'No Instructions provided') # Provides step by step instructions to user to remediate finding

        ##############################################
        # Declaring HTML variables for Email Format
        ##############################################
        severity_html = f"<b><span style='color: red;'>{severity.upper()}</span></b>"

        email_body = f"""
        <div style="text-align: center;">
        <h2> GCP Cloud event Alert notification - This is a {severity} severity alert</h2>
        </div>
        <p>This message is from {findingfromComponent} which is part of Security Command Center(SCC) :</p>
        <strong>Alert found by:</strong> {findingfromComponent}<br>
        <strong>Severity:</strong> {severity}<br>
        <strong>Finding Type:</strong> {findingType}<br>
        <strong>Status:</strong> {state}<br>
        <strong>Heading:</strong> {findingname}<br>
        <strong>Description:</strong> {description}<br>
        <strong>Link for Finding:</strong> {url}<br>

        """
        message = {
            "senderAddress": "DoNotReply@oa.mo.gov",
            "recipients":  {
                "to": [{"address": "aditya.tetali@oa.mo.gov" }],
            },
            "content": {
                "subject": "New High or Critical Severity Finding Detected",
                "plainText": "Hello world via email.",
                "html": email_body, },
        }

        poller = client.begin_send(message)
        result = poller.result()
        logging.info("Email sent successfully.")

    except Exception as ex:
        logging.error(f"Error sending email: {ex}")
