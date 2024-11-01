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
import snowflake.connector
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_der_private_key

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

secrets = ['graph_secret_email_auto','graph_client_email_auto','graph_tenant_id','jira_api_token','email','snowflake_bizops_user','snowflake_account','snowflake_key_pass','snowflake_bizops_wh','snowflake_salesmarketing_schema','snowflake_fivetran_db','snowflake_bizops_role']

fetch_secrets = get_secrets(secrets)

#Extract all secrets
extracted_secrets = {key: extract_secret_value(value) for key, value in fetch_secrets.items()}

#Secrets
jira_api_token = extracted_secrets['jira_api_token']['jira_api_token']
graph_secret = extracted_secrets['graph_secret_email_auto']['graph_secret_email_auto']
graph_client_id = extracted_secrets['graph_client_email_auto']['graph_client_email_auto']
graph_tenant_id = extracted_secrets['graph_tenant_id']['graph_tenant_id']
jira_user = extracted_secrets['email']['email']
snowflake_user = extracted_secrets['snowflake_bizops_user']['snowflake_bizops_user']
snowflake_account = extracted_secrets['snowflake_account']['snowflake_account']
snowflake_key_pass = extracted_secrets['snowflake_key_pass']['snowflake_key_pass']
snowflake_bizops_wh = extracted_secrets['snowflake_bizops_wh']['snowflake_bizops_wh']
snowflake_schema = extracted_secrets['snowflake_salesmarketing_schema']['snowflake_salesmarketing_schema']
snowflake_fivetran_db = extracted_secrets['snowflake_fivetran_db']['snowflake_fivetran_db']
snowflake_role = extracted_secrets['snowflake_bizops_role']['snowflake_bizops_role']

password = snowflake_key_pass.encode()

#AWS S3 Configuration params
s3_bucket = 'aws-glue-assets-bianalytics'
s3_key = 'BIZ_OPS_ETL_USER.p8'

#Function to download file from S3
def download_from_s3(bucket, key):
    s3_client = boto3.client('s3')
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        return response['Body'].read()
    except Exception as e:
        print(f"Error downloading from S3: {e}")
        return None

#Download the private key file from S3
key_data = download_from_s3(s3_bucket, s3_key)

#Try loading the private key as PEM
private_key = load_pem_private_key(key_data, password=password)

#Extract the private key bytes in PKCS8 format
private_key_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

#Get today in est
eastern = pytz.timezone('America/New_York')
today = datetime.now(eastern)

#Establish the bounds of the calendar dataframe
last_day_last_month = (today - relativedelta(days=1)).date().strftime('%Y-%m-%d')
first_day_in_series = (today - relativedelta(months=2)).date().strftime('%Y-%m-%d')

#Create the calendar dataframe
date_range = pd.date_range(start=first_day_in_series, end=last_day_last_month, freq='MS')
calendar_df = pd.DataFrame({
    'month_start': date_range,
    'month_end': date_range + pd.offsets.MonthEnd()
})

#Create columns to store dates as strings
calendar_df['month_start_str'] = calendar_df['month_start'].dt.strftime('%Y-%m-%d')
calendar_df['month_end_str'] = calendar_df['month_end'].dt.strftime('%Y-%m-%d') 

#Extract values from calendar dataframe to use in api request
start = calendar_df.iloc[0, 2]
end = calendar_df.iloc[1, 3]
start_res = calendar_df.iloc[1, 2]

jira_url = "https://hhaxsupport.atlassian.net"
api_endpoint = "/rest/api/3/search/"

#JQL query to fetch all in scope issues
jql_query = f"""project in (HHA, ESD, RCOSD, EAS) AND ("Primary Location" ~ IL OR "HHAX Market" ~ IL OR "State" = IL) AND ((created >= "{start}" AND created <= "{end}") or (resolved >= "{start_res}" AND resolved <= "{end}")) 
ORDER BY created ASC"""

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

        resolved_time = (issue['fields'].get('customfield_10030', {}).get('completedCycles', []))
        if resolved_time:
            resolved_time = resolved_time[0].get('elapsedTime', {}).get('millis')
        else:
            resolved_time = None

        data.append([key,response_time,resolved_time,reporter,hhax_regional_platform_tag,state,primary_location,hhax_market,associations,created,resolved,updated,payer,status_snapshot,summary,tax_id])

    df = pd.DataFrame(data, columns=['key','response_time','resolved_time','reporter','hhax_platform_region_tag','state','primary_location','hhax_market','associations','create_date','resolved_date','updated','payer','status','summary','tax_id'])
    
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

#Build a function to extract n comments from each issue
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

merged_jira_df = merged_jira_df.rename(columns={'contains_phrase': 'closed_via_automation'})

#Get latest call center data from Snowflake
ctx = snowflake.connector.connect(
    user=snowflake_user,
    account=snowflake_account,
    private_key=private_key_bytes,
    role=snowflake_role,
    warehouse=snowflake_bizops_wh)
    
today = datetime.now().date()
    
cs = ctx.cursor()
script = f"""
with 
regular_queue_data as (
select 
coalesce(sum(contacts_queued),0) as contacts_queued,
coalesce(sum(contacts_abandoned),0) as contacts_abandoned,
coalesce(sum(contacts_handled),0) as contacts_handled,
concat((round((sum(contacts_abandoned)/sum(contacts_queued)),2)*100),'%') as abandoned_rate,
coalesce(sum(contacts_answered_in_30),0) as contacts_answered_in_30_secs,
concat((round((sum(contacts_answered_in_30)/sum(contacts_handled)),2)*100),'%') as contacts_answered_in_30_secs_pct,
coalesce((avg(average_queue_answer_time)/60),0) as avg_answer_time_mins
from (select contacts_queued,contacts_abandoned,contacts_handled,contacts_answered_in_30,average_queue_answer_time from PC_FIVETRAN_DB.DBT_SALESANDMARKETING_DEPLOYMENT.FACT_UIVR
where state = 'IL' and lower(queue_name) not like '%callback%' and date_from_parts(initiation_year,initiation_month,initiation_day) >= '{start_res}' and date_from_parts(initiation_year,initiation_month,initiation_day) < '{today}')),

callback_data as (
select 
coalesce(sum(contacts_queued),0) as contacts_queued,
coalesce(sum(contacts_abandoned),0) as contacts_abandoned,
coalesce(sum(contacts_handled),0) as contacts_handled,
concat((round((sum(contacts_abandoned)/sum(contacts_queued)),2)*100),'%') as abandoned_rate,
coalesce(sum(contacts_answered_in_30),0) as contacts_answered_in_30_secs,
concat((round((sum(contacts_answered_in_30)/sum(contacts_handled)),2)*100),'%') as contacts_answered_in_30_secs_pct,
coalesce((avg(average_queue_answer_time)/60),0) as avg_answer_time_mins
from (select contacts_queued,contacts_abandoned,contacts_handled,contacts_answered_in_30,average_queue_answer_time from PC_FIVETRAN_DB.DBT_SALESANDMARKETING_DEPLOYMENT.FACT_UIVR
where state = 'IL' and lower(queue_name) like '%callback%' and date_from_parts(initiation_year,initiation_month,initiation_day) >= '{start_res}' and date_from_parts(initiation_year,initiation_month,initiation_day) < '{today}'))

select * from regular_queue_data
union all
select * from callback_data
"""
payload = cs.execute(script)
phone_df = pd.DataFrame.from_records(iter(payload), columns=[x[0] for x in payload.description])

#Do some data cleanup of call center dataframe
phone_df['MONTH'] = start_res
phone_df.loc[0:1, 'NAME'] = ['Illinois', 'Illinois-Callback']

col_order = ['MONTH','NAME','CONTACTS_QUEUED','CONTACTS_ABANDONED','CONTACTS_HANDLED','ABANDONED_RATE','CONTACTS_ANSWERED_IN_30_SECS','CONTACTS_ANSWERED_IN_30_SECS_PCT','AVG_ANSWER_TIME_MINS']

aggregated_df = phone_df[col_order]

aggregated_df['AVG_ANSWER_TIME(mins)'] = aggregated_df['AVG_ANSWER_TIME_MINS'].astype(float)
aggregated_df['AVG_ANSWER_TIME(mins)'] = aggregated_df['AVG_ANSWER_TIME(mins)'].round(2)

aggregated_df = aggregated_df.rename(columns={'NAME': 'QUEUE'})

aggregated_df.columns = aggregated_df.columns.str.lower()

aggregated_df.drop(columns={'avg_answer_time_mins'},inplace=True)

#s3 information to extract ticket stage definitions
s3_bucket = 'aws-glue-assets-bianalytics'
s3_key = 'Ticket_Stages.xlsx'

#Function to download stages file from s3
def download_from_s3(bucket, key):
    s3_client = boto3.client('s3')
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        return response['Body'].read()
    except Exception as e:
        print(f"Error downloading from S3: {e}")
        return None

#Download the stages file from S3
stages_file = download_from_s3(s3_bucket, s3_key)

#Make stages file into dataframe
stages_df = pd.read_excel(io.BytesIO(stages_file))

#Establish date bounds for subsequent dataframes
start_filter = calendar_df.iloc[1, 0].date()
end_filter_last = calendar_df.iloc[0, 0].date()

#Convert milliseconds into minutes
merged_jira_df['elapsed_time_resolved_mins'] = merged_jira_df['resolved_time']/60000
merged_jira_df['elapsed_time_response_mins'] = merged_jira_df['response_time']/60000

#Convert datetime dates to dates for easy pivot and aggregation
merged_jira_df['created'] = pd.to_datetime(merged_jira_df['create_date'], utc=True)
merged_jira_df['created'] = merged_jira_df['created'].dt.tz_convert('US/Eastern')
merged_jira_df['created'] = pd.to_datetime(merged_jira_df['created']).dt.date
merged_jira_df['resolved'] = pd.to_datetime(merged_jira_df['resolved_date'], utc=True)
merged_jira_df['resolved'] = merged_jira_df['resolved'].dt.tz_convert('US/Eastern')
merged_jira_df['resolved'] = pd.to_datetime(merged_jira_df['resolved']).dt.date

#Isolated created and resolved dataframes for reporting period
current_create_filtered_df = merged_jira_df[merged_jira_df['created'] >= start_filter]
current_resolved_filtered_df = merged_jira_df[merged_jira_df['resolved'] >= start_filter]

#Isolate created dataframe from reporting month minus 1
last_create_filtered_df = merged_jira_df[(merged_jira_df['created'] < start_filter) & (merged_jira_df['created'] >= end_filter_last)]

#Extract the project prefix, aggregate and pivot results for created and resolved dataframes
current_create_filtered_df['prefix'] = current_create_filtered_df['key'].str.split('-').str[0]
current_resolved_filtered_df['prefix'] = current_resolved_filtered_df['key'].str.split('-').str[0]
grouped_created_df = current_create_filtered_df.groupby(['prefix', 'created']).size().reset_index(name='count')
pivoted_created_df = grouped_created_df.pivot(index='created', columns='prefix', values='count').reset_index()
pivoted_created_df.fillna(0, inplace=True)
pivoted_created_df['Total'] = pivoted_created_df.select_dtypes(include=['int64', 'float64']).sum(axis=1)
grouped_resolved_df = current_resolved_filtered_df.groupby(['prefix', 'resolved']).size().reset_index(name='count')
pivoted_resolved_df = grouped_resolved_df.pivot(index='resolved', columns='prefix', values='count').reset_index()
pivoted_resolved_df.fillna(0, inplace=True)
pivoted_resolved_df['Total'] = pivoted_resolved_df.select_dtypes(include=['int64', 'float64']).sum(axis=1)

#Conduct the match exercise to determine reporters that have opened tickets in both the reporting month and reporting month minus 1
current_create_filtered_df['has_match'] = current_create_filtered_df['reporter'].isin(last_create_filtered_df['reporter'])
last_create_filtered_df['has_match'] = last_create_filtered_df['reporter'].isin(current_create_filtered_df['reporter'])

#Build month over month view
key_cols = ['reporter','tax_id', 'associations', 'key','created','resolved','status','summary','hhax_platform_region_tag','state','primary_location','hhax_market']
last_w_matches = last_create_filtered_df[last_create_filtered_df['has_match']].copy()
last_w_matches_final = last_w_matches.loc[:,key_cols]
this_w_matches = current_create_filtered_df[current_create_filtered_df['has_match']].copy()
this_w_matches_final = this_w_matches.loc[:,key_cols]
final_matched_df = pd.concat([this_w_matches_final,last_w_matches_final])

#Conduct SLA test, build SLA summary dataframe
current_resolved_filtered_df['resolved_10_bd'] = current_resolved_filtered_df['elapsed_time_resolved_mins'] <= 14400

pivoted_sla_table = current_resolved_filtered_df[current_resolved_filtered_df['prefix'] != 'RCOSD'].groupby(['prefix']).agg(
    closed=('prefix', 'size'),
    met_sla=('resolved_10_bd', 'sum')
).reset_index()

pivoted_sla_table['pct'] = pivoted_sla_table['met_sla'] / pivoted_sla_table['closed']
pivoted_sla_table['pct'] = (pivoted_sla_table['pct'] * 100).round(2).astype(str) + '%'

#Create total row for sla summary dataframe
row_totals = pivoted_sla_table.agg({
   'closed': 'sum',
   'met_sla': 'sum'
}).to_frame().T

#Calculate aggregate sla percentage
row_totals['pct'] = (row_totals['met_sla'] / row_totals['closed'] * 100).round(2).astype(str) + '%'

#Add a prefix label for the totals row
row_totals['prefix'] = 'Total'

#Combine original sla dataframe with totals
pivoted_sla_table_final = pd.concat([pivoted_sla_table, row_totals], ignore_index=True)

pivoted_sla_table.rename(columns={'prefix':'project'},inplace=True)

#Do some data cleanup
current_create_filtered_df.drop(columns=['response_time','resolved_time','created','resolved','prefix','has_match','issue_key'],inplace=True)
current_resolved_filtered_df.drop(columns=['response_time','resolved_time','created','resolved','prefix','issue_key'],inplace=True)

#Map all of the previously created dataframes to their eventual excel tab name
csv_mappings = {
    'Statuses':stages_df,
    'JIRA Created Details':current_create_filtered_df,
    'JIRA Resolved Details':current_resolved_filtered_df,
    'JIRA Created Summary':pivoted_created_df,
    'JIRA Resolved Summary':pivoted_resolved_df,
    'SLA Summary':pivoted_sla_table_final,
    'MoM Matches':final_matched_df,
    'AWS':aggregated_df}

#Build the email date string for dynamic file naming and subjects, use the dates from the calendar dataframe
reporting_month_dt = datetime.strptime(start_res, '%Y-%m-%d')
reporting_month = reporting_month_dt.strftime('%B %Y')
date_string = str(reporting_month)

excel_buffer = io.BytesIO()

#Write the pandas dataframes to a single excel file
with pd.ExcelWriter(excel_buffer, engine='openpyxl') as excel_writer:
    for sheet_name, dataframe in csv_mappings.items():
        if sheet_name == 'Statuses':
            dataframe.to_excel(excel_writer, sheet_name=sheet_name, index=False, header=True)
        else:
            index_param = False
            dataframe.to_excel(excel_writer, sheet_name=sheet_name, index=index_param)
    
    #Adjust column widths
    workbook = excel_writer.book
    worksheet = workbook['Statuses']
    worksheet.column_dimensions['A'].width = 50
    worksheet.column_dimensions['B'].width = 100
    worksheet.column_dimensions['C'].width = 150
    worksheet = workbook['JIRA Resolved Summary']
    worksheet.column_dimensions['A'].width = 50
    worksheet = workbook['JIRA Created Summary']
    worksheet.column_dimensions['A'].width = 50
    worksheet = workbook['JIRA Created Details']
    worksheet.column_dimensions['B'].width = 50
    worksheet.column_dimensions['C'].width = 50
    worksheet.column_dimensions['H'].width = 50
    worksheet.column_dimensions['I'].width = 50
    worksheet.column_dimensions['J'].width = 50
    worksheet = workbook['JIRA Resolved Details']
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

#Fetch access token from graph oauth endpoint
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

#Service account email address
from_email = 'bi-analytics@hhaexchange.com'
#List of internal email recipients
to_email = ['mdunlap@hhaexchange.com','dsweeney@hhaexchange.com','jmonserrat@hhaexchange.com','sbowen@hhaexchange.com','tprause@hhaexchange.com']
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
ctx.close()