import boto3
import openpyxl
import pytz
import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
from datetime import datetime, timedelta,timezone,date,time
from dateutil.relativedelta import relativedelta
import urllib
import json
import openpyxl
import re
import io
from io import BytesIO
import base64

#Function to fetch secrets from Secrets Manager
def get_secrets(secret_names, region_name="us-east-1"):
    secrets = {}
    
    client = boto3.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    
    for secret_name in secret_names:
        try:
            get_secret_value_response = client.get_secret_value(
                SecretId=secret_name)
        except Exception as e:
                raise e
        else:
            if 'SecretString' in get_secret_value_response:
                secrets[secret_name] = get_secret_value_response['SecretString']
            else:
                secrets[secret_name] = base64.b64decode(get_secret_value_response['SecretBinary'])

    return secrets
    
def extract_secret_value(data):
    if isinstance(data, str):
        return json.loads(data)
    return data

secrets = ['graph_secret_email_auto','graph_client_email_auto','graph_tenant_id','jira_api_token','email','aws_other_instance_id','aws_secret_key','aws_access_key','aws_arn']

fetch_secrets = get_secrets(secrets)

#Extract all secrets
extracted_secrets = {key: extract_secret_value(value) for key, value in fetch_secrets.items()}

#Secrets
jira_api_token = extracted_secrets['jira_api_token']['jira_api_token']
graph_secret = extracted_secrets['graph_secret_email_auto']['graph_secret_email_auto']
graph_client_id = extracted_secrets['graph_client_email_auto']['graph_client_email_auto']
graph_tenant_id = extracted_secrets['graph_tenant_id']['graph_tenant_id']
jira_user = extracted_secrets['email']['email']
aws_secret_key = extracted_secrets['aws_secret_key']['aws_secret_key']
aws_instance_id = extracted_secrets['aws_other_instance_id']['aws_other_instance_id']
aws_access_key = extracted_secrets['aws_access_key']['aws_access_key']
aws_arn = extracted_secrets['aws_arn']['aws_arn']

jira_url = "https://hhaxsupport.atlassian.net"
api_endpoint = "/rest/api/3/search/"

#JQL query to fetch all in scope issues
jql_query = """project in (HHA, ESD, RCOSD, EAS) AND ("Primary Location" ~ IL OR "HHAX Market" ~ IL OR "State" = IL) AND (created >= startOfMonth(-1) AND created < startOfMonth()) ORDER BY created ASC"""

jql_query_encoded = urllib.parse.quote(jql_query)

startAt = 0
maxResults = 100

all_issues = []

#Make a request to the JIRA api to get all required fields, with the exception of comments
while True:
    api_url = f"{jira_url}{api_endpoint}?jql={jql_query_encoded}&startAt={startAt}&maxResults={maxResults}"

    response = requests.get(
        api_url,
        auth=HTTPBasicAuth(jira_user, jira_api_token),
        headers={
            "Accept": "application/json"
        }
    )

    json_response = response.json()

    if response.status_code == 200:
        all_issues.extend(json_response['issues'])

        if json_response['total'] == len(all_issues):
            break
        else:
            startAt += maxResults
    else:
        break

if isinstance(json_response, str):
    json_response = json.loads(json_response)

issues = all_issues

#Parse the JSON payload, store results in a pandas dataframe
if isinstance(issues, list):
    data = []

    for issue in issues:

        key = issue['key']
        hhax_market = issue['fields'].get('customfield_10206', None)
        primary_location = issue['fields'].get('customfield_12755', None)
        customfield_11540_obj = issue['fields'].get('customfield_11540', {})
        if customfield_11540_obj:
            state = customfield_11540_obj.get('value', None)
        else:
            state = None
        created = issue['fields'].get('created', None)
        payer_obj = issue['fields'].get('customfield_10219', {})
        if payer_obj:
            payer = payer_obj.get('value', None)
        else:
            payer = None
        summary = issue['fields'].get('summary', None)
        resolved = issue['fields'].get('resolutiondate',None)
        status_snapshot = issue['fields'].get('status', {}).get('name', None)
        tax_id = issue['fields'].get('customfield_10204',None)
        reporter_obj = issue['fields'].get('reporter',{})
        if reporter_obj:
            reporter = reporter_obj.get('emailAddress', None)
        else:
            reporter = None
        updated = issue['fields'].get('updated',None)
        associations_obj = issue['fields'].get('customfield_11478', {})
        if associations_obj and 'content' in associations_obj:
            content_list = associations_obj['content']
            if content_list and 'content' in content_list[0]:
                text_content = content_list[0]['content']
                if text_content and 'text' in text_content[0]:
                    associations = text_content[0]['text']
                else:
                    associations = None
            else:
                associations = None
        else:
            associations = None
        customfield_10236_obj = issue['fields'].get('customfield_10236', {})
        if customfield_10236_obj and 'content' in customfield_10236_obj:
            content_list = customfield_10236_obj['content']
            if content_list and 'content' in content_list[0]:
                text_content = content_list[0]['content']
                if text_content and 'text' in text_content[0]:
                    hhax_regional_platform_tag = text_content[0]['text']
                else:
                    hhax_regional_platform_tag = None
            else:
                hhax_regional_platform_tag = None
        else:
            hhax_regional_platform_tag = None

        response_time = (issue['fields'].get('customfield_10031', {}).get('completedCycles', []))
        if response_time:
            response_time = response_time[0].get('elapsedTime', {}).get('millis')
        else:
            response_time = None

        data.append([key,response_time,reporter,hhax_regional_platform_tag,state,primary_location,hhax_market,associations,created,resolved,updated,payer,status_snapshot,summary,tax_id])

    df = pd.DataFrame(data, columns=['key','response_time','reporter','hhax_platform_region_tag','state','primary_location','hhax_market','associations','create_date','resolved_date','updated','payer','status','summary','tax_id'])

#Store each key from the first JSON payload in a list
keys = list(df['key'])

comments = []

#Iterate through each key in the keys list, call the issue endpoint to extract all comments for each issue. Using comments data to determine if ticket was closed via automation
jira_url = "https://hhaxsupport.atlassian.net"
api_endpoint = "/rest/api/3/issue/"
maxResults = 50000

for key in keys:
    startAt = 0
    while True:
        api_url = f"{jira_url}{api_endpoint}{key}?startAt={startAt}&maxResults={maxResults}"

        response = requests.get(
            api_url,
            auth=HTTPBasicAuth(jira_user, jira_api_token),
            headers={
                "Accept": "application/json"
            })

        json_response = response.json()

        if response.status_code == 200:
            comments.append(json_response)

            if len(json_response) < maxResults:
                break
            else:
                startAt += maxResults
        else:
            break

#Build a function to extract n comments for each issue
def extract_comment_texts_dates_for_dataframe(issues, num_comments_per_issue):
    comments_data = []

    for issue in issues:
        issue_key = issue.get('key')
        comments = issue.get('fields', {}).get('comment', {}).get('comments', [])
        comments_to_extract = comments[:num_comments_per_issue]

        for i, comment in enumerate(comments_to_extract, start=1):
            comment_text = " ".join([text_block['text'] for content_block in comment.get('body', {}).get('content', []) 
                                    if 'content' in content_block for text_block in content_block['content'] 
                                    if text_block.get('type') == 'text' and 'text' in text_block])
            comment_date = comment.get('created')
            author_email = comment.get('author', {}).get('emailAddress')
            author_display_name = comment.get('author', {}).get('displayName')
            author_contact = author_email if author_email else author_display_name

            comments_data.append({
                'issue_key': issue_key,
                'comment_number': f'Comment {i}',
                'comment_body': comment_text,
                'comment_date': comment_date,
                'author_contact': author_contact
            })

    return comments_data

#Use a 50 comment assumption
num_comments_per_issue = 50
extracted_comments = extract_comment_texts_dates_for_dataframe(comments, num_comments_per_issue)
#Store extracted comments in a pandas dataframe
comments_df = pd.DataFrame(extracted_comments)

pivoted_df = pd.DataFrame()

#Pivot the comment dataframe, assuming up to 50 comments per issue
for i in range(1, 51):
    temp_df = comments_df[comments_df['comment_number'] == f'Comment {i}'].copy()
    temp_df.set_index('issue_key', inplace=True)
    
    #Rename columns dynamically based on the comment number
    temp_df.rename(columns={
        'comment_body': f'comment {i} body',
        'comment_date': f'comment {i} date',
        'author_contact': f'comment {i} author'
    }, inplace=True)
    
    #Drop the comment_number column as it's redundant now
    temp_df.drop('comment_number', axis=1, inplace=True)
    
    if pivoted_df.empty:
        pivoted_df = temp_df
    else:
        pivoted_df = pivoted_df.join(temp_df, how='outer')

#Reset index to bring the issue key back as a column
pivoted_df.reset_index(inplace=True)

#Build a function to check if phrase used in closed via automation workflow is present in any comment body for each issue
def check_for_phrase(row, phrase):
    for i in range(1, 51):
        comment_col = f'comment {i} body'
        if pd.notna(row[comment_col]) and phrase in row[comment_col]:
            return True
    return False

#Phrase always present on comments closed via automation
phrase = "At this time, we are going to close your request"
pivoted_df['contains_phrase'] = pivoted_df.apply(check_for_phrase, axis=1, phrase=phrase)
isolated_pivoted_df = pivoted_df[['issue_key','contains_phrase']]

#Merge the dataframe from the initial jira request with the dataframe with the comment data
merged_jira_df = pd.merge(df,isolated_pivoted_df,left_on='key',right_on='issue_key')

#Convert the response time sla value from milliseconds to minutes
merged_jira_df['response_time_(mins)'] = merged_jira_df['response_time']/60000

#Start to build the JIRA summary table
summary_df = merged_jira_df

summary_df['create_date'] = pd.to_datetime(summary_df['create_date']).dt.date
summary_df['resolved_date'] = pd.to_datetime(summary_df['resolved_date'], errors='coerce').dt.date

#Extract the project prefix for aggregation
summary_df['project_prefix'] = summary_df['key'].apply(lambda x: re.match(r'^[A-Z]+', x).group(0) if re.match(r'^[A-Z]+', x) else '')

pivot_data = summary_df.groupby(['create_date', 'project_prefix'])['key'].count().reset_index()

pivot_data = pd.pivot_table(
    pivot_data,
    index='create_date',
    columns='project_prefix',
    values='key',
    aggfunc='sum',
    fill_value=0
)

pivot_data['created'] = summary_df.groupby('create_date')['key'].count()
#Of the tickets created on that date, how many are now closed?
pivot_data['closed'] = summary_df[summary_df['resolved_date'].notna()].groupby('create_date')['key'].count().reindex(pivot_data.index, fill_value=0)
#Convert timestamps to date datatype
merged_jira_df['create_date'] = pd.to_datetime(merged_jira_df['create_date']).dt.date
merged_jira_df['resolved_date'] = pd.to_datetime(merged_jira_df['resolved_date'], errors='coerce').dt.date
merged_jira_df['updated'] = pd.to_datetime(merged_jira_df['updated'], errors='coerce').dt.date

merged_jira_df.drop(columns=['issue_key','response_time','project_prefix'],inplace=True)

merged_jira_df = merged_jira_df.rename(columns={'contains_phrase': 'closed_via_automation'})

#Create a boto3 session
session = boto3.Session(
    aws_access_key_id=aws_access_key,
    aws_secret_access_key=aws_secret_key,
    region_name='us-east-1')

connect_client = session.client('connect',endpoint_url='https://connect.us-east-1.amazonaws.com')

queues = connect_client.list_queues(InstanceId='2985c653-8593-4835-a64e-5ae84d77f978',QueueTypes=['STANDARD'])

#Fetch all instance queue data for use later
queue_df = pd.DataFrame(queues['QueueSummaryList'])

today = datetime.now()
#Start date for report is first day of previous month
first_of_month = today - relativedelta(months=1)
#End date for report is last day of previous month
end_of_month = today - timedelta(days=1)

#Localize, and ensure we are capturing all data in range
eastern = pytz.timezone('US/Eastern')
start_date = eastern.localize(datetime.combine(first_of_month, datetime.min.time()))
end_date = eastern.localize(datetime.combine(end_of_month, datetime.max.time()))

data = []

current_date = start_date

#Get AWS data for each day in the stated range
while current_date <= end_date:
    next_date = current_date + timedelta(days=1)
    
    response = connect_client.get_metric_data_v2(
        ResourceArn=f'arn:aws:connect:us-east-1:{aws_arn}:instance/{aws_instance_id}',
        StartTime=current_date,
        EndTime=next_date,
        Filters=[
            {
                'FilterKey': 'QUEUE',
                'FilterValues': ['97c6b15c-2464-41da-a6c0-4d1be020d607'] 
            },
        ],
        Groupings=['QUEUE'],
        Metrics=[
            {
                'Name': 'CONTACTS_QUEUED',
            },
            {
                'Name': 'AVG_QUEUE_ANSWER_TIME',
            },
            {
                'Name': 'CONTACTS_ABANDONED',
            },
        ],
        MaxResults=100
    )
    
    #Parse JSON payload, store results
    for metric_result in response.get('MetricResults', []):
        queue_id = metric_result['Dimensions']['QUEUE']
        for metric_data in metric_result.get('Collections', []):
            metric_name = metric_data.get('Metric', {}).get('Name', 'Unknown')
            try:
                value = metric_data['Value']
            except KeyError:
                value = 0
            data.append([current_date.date(), queue_id, metric_name, value])
    
    current_date = next_date

#Pandas dataframe with parsed AWS JSON payload data
phone_df_temp = pd.DataFrame(data, columns=['Date','Queue_ID','MetricName', 'Value'])

phone_df_temp.columns = phone_df_temp.columns.str.upper()

#Function to rename some column names
def custom_rename(column_name):
    if column_name == "DATE":
        return "Date"
    elif column_name == "METRICNAME":
        return "MetricName"
    elif column_name == "VALUE":
        return "Value"
    elif column_name == "QUEUE_ID":
        return "Queue_ID"
    else:
        return column_name

phone_df = phone_df_temp.rename(columns=custom_rename)

phone_df_with_queue_names = phone_df.merge(queue_df[['Id', 'Name']], left_on='Queue_ID', right_on = 'Id',how='inner')

pivoted_phone_df_with_queue_names = phone_df_with_queue_names.pivot(index=['Date','Name','Queue_ID'], columns='MetricName', values='Value').reset_index()

pivoted_phone_df_with_queue_names['MONTH'] = pd.to_datetime(pivoted_phone_df_with_queue_names['Date']).dt.to_period('M')

#Aggregate the daily date to monthly level of detail
aggregated_df = pivoted_phone_df_with_queue_names.groupby(['MONTH', 'Name']).agg({
    'AVG_QUEUE_ANSWER_TIME': 'mean',
    'CONTACTS_ABANDONED': 'sum',
    'CONTACTS_QUEUED': 'sum'
}).reset_index()

#Convert seconds to minutes
aggregated_df['AVG_ANSWER_TIME (mins)'] = (aggregated_df['AVG_QUEUE_ANSWER_TIME']/60).round(2)

#Calculate the abandoned rate
aggregated_df['ABANDONED_RATE'] = (((aggregated_df['CONTACTS_ABANDONED'] / aggregated_df['CONTACTS_QUEUED']) * 100).round(2)).astype(str) + '%'

aggregated_df.drop(columns=['AVG_QUEUE_ANSWER_TIME'],inplace=True)
aggregated_df.columns = aggregated_df.columns.str.upper()

#s3 config 
s3_bucket = 'aws-glue-assets-bianalytics'
s3_key = 'Ticket_Stages.xlsx'

#Download stages file from s3
def download_from_s3(bucket, key):
    s3_client = boto3.client('s3')
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        return response['Body'].read()
    except Exception as e:
        print(f"Error downloading from S3: {e}")
        return None

# Download the private key file from S3
stages_file = download_from_s3(s3_bucket, s3_key)

stages_df = pd.read_excel(io.BytesIO(stages_file))

aggregated_df = aggregated_df[['MONTH','NAME','CONTACTS_QUEUED', 'CONTACTS_ABANDONED','ABANDONED_RATE','AVG_ANSWER_TIME (MINS)']]

aggregated_df = aggregated_df.rename(columns={'Name': 'QUEUE'})

aggregated_df.columns = aggregated_df.columns.str.lower()

#Map all of the previously created dataframes to their eventual excel tab name
csv_mappings = {
    'Statuses':stages_df,
    'JIRA':merged_jira_df,
    'JIRA Summary':pivot_data,
    'AWS':aggregated_df}

#Build the email date string for dynamic file naming and subjects, use the dates from the AWS call center request
reporting_month = start_date.strftime('%B %Y')
date_string = str(reporting_month)

excel_buffer = io.BytesIO()

#Write the pandas dataframes to a single excel file
with pd.ExcelWriter(excel_buffer, engine='openpyxl') as excel_writer:
    for sheet_name, dataframe in csv_mappings.items():
        if sheet_name == 'Statuses':
            dataframe.to_excel(excel_writer, sheet_name=sheet_name, index=False, header=True)
        else:
            index_param = True if sheet_name == 'JIRA Summary' else False
            dataframe.to_excel(excel_writer, sheet_name=sheet_name, index=index_param)
    
    #Adjust column widths
    workbook = excel_writer.book
    worksheet = workbook['Statuses']
    worksheet.column_dimensions['A'].width = 50
    worksheet.column_dimensions['B'].width = 100
    worksheet.column_dimensions['C'].width = 150
    worksheet = workbook['JIRA Summary']
    worksheet.column_dimensions['A'].width = 50
    worksheet = workbook['JIRA']
    worksheet.column_dimensions['B'].width = 50
    worksheet.column_dimensions['C'].width = 50
    worksheet.column_dimensions['H'].width = 50
    worksheet.column_dimensions['I'].width = 50
    worksheet.column_dimensions['J'].width = 50
    
excel_buffer.seek(0)

#Encode excel file in base64
attachment_base64 = base64.b64encode(excel_buffer.read()).decode('utf-8')

#Load graph secrets to use in email automation
client_id = graph_client_id
client_secret = graph_secret
tenant_id = graph_tenant_id

#Build the request to get access token from graph oauth endpoint
url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}
data = {
    'grant_type': 'client_credentials',
    'client_id': client_id,
    'client_secret': client_secret,
    'scope': 'https://graph.microsoft.com/.default'
}
response = requests.post(url, headers=headers, data=data)
response.raise_for_status()
#Parse the access token from the JSON payload, store value for email send request
access_token = response.json().get('access_token')

#The email is going to come from my email
from_email = 'mdunlap@hhaexchange.com'
#Email recipients
#to_email = ['cward@hhaexchange.com', 'dsweeney@hhaexchange.com','tprause@hhaexchange.com','sbowen@hhaexchange.com']
to_email = ['mdunlap@hhaexchange.com','mhirrlinger@hhaexchange.com']
subject = 'IL Monthly Report' + ' '+ '-' +' '+ date_string
body = 'IL Monthly Report' + ' '+ '-' + ' '+ date_string

email_recipients = [{"emailAddress": {"address": email}} for email in to_email]

#Configure the attachment
attachment = {
    '@odata.type': '#microsoft.graph.fileAttachment',
    'name': f'IL Monthly Report - {date_string}.xlsx',
    'contentType': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'contentBytes': attachment_base64
}

send_mail_url = f'https://graph.microsoft.com/v1.0/users/{from_email}/sendMail'
email_msg = {
    'message': {
        'subject': subject,
        'body': {
            'contentType': "Text",
            'content': body
        },
        'toRecipients': email_recipients,
        'attachments': [attachment]
    }
}

headers = {
    'Authorization': f'Bearer {access_token}',
    'Content-Type': 'application/json'
}

#Send the email with the excel attachment
response = requests.post(send_mail_url, headers=headers, json=email_msg)
response.raise_for_status()