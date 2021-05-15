import io
import os
import csv
import hashlib
import base64
import boto3
import json
import requests
import collections
# import pandas as pd
from requests.auth import HTTPBasicAuth
from botocore.exceptions import ClientError
import simplejson as json
import argparse
import pprint
import datetime
import pandas as pd


# An example to get the remaining rate limit using the Github GraphQL API.
parser = argparse.ArgumentParser(
    description="Beta GraphQL query for Github Vulnerabilities.")
parser.add_argument(
    '--owner', help='owner or organization name where repository is located')
parser.add_argument(
    '--repository', help='github repository to check for known vulnerabilities')
parser.add_argument('--token', help='github token that can query repo')
# parser.add_argument('--jirausername', help='github token that can query repo')
# parser.add_argument('--jiratoken', help='github token that can query repo')

args = parser.parse_args()

DYNAMODB = boto3.resource('dynamodb',aws_access_key_id="***",aws_secret_access_key="***",region_name="us-west-2",aws_session_token="***")
DYNAMODB_TABLE = DYNAMODB.Table('<table_name>')

github_headers = {
    "Authorization": "Bearer {}".format(args.token),
    "Accept": "application/json"
}

jira_headers = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}

def run_query(query, args):
    variables = {
        "repoName": args.repository,
        "owner": args.owner
    }
    request = requests.post('https://api.github.com/graphql', json={'query': query, 'variables': variables}, headers=github_headers)
    if request.status_code == 200:
        return request.json()
    else:
        raise Exception("Query failed to run by returning code of {}. {}".format(
            request.status_code, query))

query = """query($repoName: String!, $owner: String!)
{
  repository(name: $repoName , owner: $owner ) {
    vulnerabilityAlerts(first: 100) {
      # totalCount
      # pageInfo {
      #   hasNextPage
      #   hasPreviousPage
      #   startCursor
      #   endCursor
      # }
      nodes {
        id
        createdAt
        vulnerableRequirements
        securityVulnerability {
          # advisory {
          #       description
          #       identifiers {
          #         value
          #       }
          #     }
          severity
          package {
            ecosystem
            name
          }
          vulnerableVersionRange
        }
      }
    }
  }
}
"""

result = run_query(query, args)  # Execute the query

#### Creation of CSVs from dump based on severity
a=result['data']['repository']['vulnerabilityAlerts']['nodes']
json_file_path = "./data.json"
csv_file_path="./data_file.csv"
with open(json_file_path, 'w', encoding='utf-8', errors='ignore') as f:
  f.write(json.dumps(a, ensure_ascii=False, indent=2))

with open(json_file_path) as infile:
    jsondata = json.loads(infile.read())

with open(csv_file_path, 'w') as outfile:
    f = csv.writer(outfile)
    f.writerow(["id","createdAt","vulnerableRequirements","securityVulnerability__severity","securityVulnerability__package__ecosystem","securityVulnerability__package__name","securityVulnerability__vulnerableVersionRange"])
    for i in jsondata:
      
      f.writerow([i["id"],i["createdAt"],i["vulnerableRequirements"],i["securityVulnerability"]["severity"],i["securityVulnerability"]["package"]["ecosystem"],i["securityVulnerability"]["package"]["name"],i["securityVulnerability"]["vulnerableVersionRange"]])


df = pd.read_csv(csv_file_path)

df = df.sort_values('securityVulnerability__severity').assign(NewColumn='NewColumnValue')
df.drop(df.columns[len(df.columns)-1], axis=1, inplace=True)
# print(df)
for i, g in df.groupby('securityVulnerability__severity'):
    g.to_csv('{}.csv'.format(i), header=True, index_label=False, index=False)

##### Creation of tickets based on severity from CSVs
def critical_lambda_handler(event, context):
  data = {}
  with open('CRITICAL.csv', encoding='utf-8') as csvf:
    csvReader = csv.DictReader(csvf)
    for rows in csvReader:
      key = rows['securityVulnerability__package__name']
      data[key] = rows
  # print(type(data))
  final_data = {}
  for key in data.keys():
    final_data[key] = data[key]['securityVulnerability__vulnerableVersionRange']
    
  vuln_mapping = "\n".join([f"{key}: {value}" for key,value in final_data.items()])  
    
  # data_result = json.dumps(data)
  data_result = "Security vulnerability issues found in project - %s - CRITICAL" % args.repository
  hash_object = hashlib.sha256(data_result.encode('utf-8'))
  hash_key = hash_object.hexdigest()
  # print(hash_key)

  search_item = {'ID': hash_key}
  item_response = DYNAMODB_TABLE.get_item(Key={'ID': hash_key})
  if 'Item' not in item_response:
      critical_payload=json.dumps(
        {
          "fields": {
            "project":
            {
              "key": "WSH"
            },
            "summary": "Security vulnerability issues found in project - %s - CRITICAL" % args.repository,
            "description": "Following are the and list of vulnerabilities found for the above project: \n {code:bash}%s{code}\n Please access security alerts from here: [Dependabot URL | https://github.com/<org_name>/%s/security/dependabot]" % (vuln_mapping,args.repository), 
            "issuetype": {
                "name": "Bug"
            },
            "priority": {
              "name": "P0"
            }
          }
        }
      )
      # print(payload)
      url = "https://<org_name>.atlassian.net/rest/api/2/issue"
      response=requests.post(url,headers=jira_headers,data=critical_payload,auth=("<jira_api_user_emailID>","<jira_api_token>"))
      data=response.json()
      print(data)
      item = {
          'ID': hash_key,
          'KEY': data['key']
          # 'TTL': int(time.time()) + 2419200
      }
      DYNAMODB_TABLE.put_item(Item=item)
  else:
    item = item_response.get('Item')
    item_key_response = item.get('KEY')
    print(item_key_response)
    payload = json.dumps({
        "update": {
            "description": [
              {
                "set": "Following are the and list of vulnerabilities found for the above project: \n {code:bash}%s{code}\n Please access security alerts from here: [Dependabot URL | https://github.com/<org_name>/%s/security/dependabot]" % (vuln_mapping,args.repository)
              }
            ]
        }
    }
    )
    update_url = "https://<org_name>.atlassian.net/rest/api/2/issue/%s" % (item_key_response)
    response=requests.request("PUT",update_url,headers=jira_headers,data=payload,auth=("<jira_api_user_emailID>","<jira_api_token>"))
    # data=response.json()
    # print(data)
  return None

def high_lambda_handler(event, context):
  data = {}
  with open('HIGH.csv', encoding='utf-8') as csvf:
    csvReader = csv.DictReader(csvf)
    for rows in csvReader:
      key = rows['securityVulnerability__package__name']
      data[key] = rows
  # print(type(data))
  final_data = {}
  for key in data.keys():
    final_data[key] = data[key]['securityVulnerability__vulnerableVersionRange']
    
  vuln_mapping = "\n".join([f"{key}: {value}" for key,value in final_data.items()])  
    
  data_result = "Security vulnerability issues found in project - %s - HIGH" % args.repository
  hash_object = hashlib.sha256(data_result.encode('utf-8'))
  hash_key = hash_object.hexdigest()
  # print(hash_key)

  search_item = {'ID': hash_key}
  item_response = DYNAMODB_TABLE.get_item(Key={'ID': hash_key})
  if 'Item' not in item_response:
      high_payload=json.dumps(
        {
          "fields": {
            "project":
            {
              "key": "WSH"
            },
            "summary": "Security vulnerability issues found in project - %s - HIGH" % args.repository,
            "description": "Following are the and list of vulnerabilities found for the above project: \n {code:bash}%s{code}\n Please access security alerts from here: [Dependabot URL | https://github.com/<org_name>/%s/security/dependabot]" % (vuln_mapping,args.repository), 
            "issuetype": {
                "name": "Bug"
            },
            "priority": {
              "name": "P1"
            }
          }
        }
      )
      # print(payload)
      url = "https://<org_name>.atlassian.net/rest/api/2/issue"
      response=requests.post(url,headers=jira_headers,data=high_payload,auth=("<jira_api_user_emailID>","<jira_api_token>"))
      data=response.json()
      print(data)
      item = {
          'ID': hash_key,
          'KEY': data['key']
          # 'TTL': int(time.time()) + 2419200
      }
      DYNAMODB_TABLE.put_item(Item=item)
  else:
    item = item_response.get('Item')
    item_key_response = item.get('KEY')
    print(item_key_response)
    payload = json.dumps({
        "update": {
            "description": [
              {
                "set": "Following are the and list of vulnerabilities found for the above project: \n {code:bash}%s{code}\n Please access security alerts from here: [Dependabot URL | https://github.com/<org_name>/%s/security/dependabot]" % (vuln_mapping,args.repository)
              }
            ]
        }
    }
    )
    update_url = "https://<org_name>.atlassian.net/rest/api/2/issue/%s" % (item_key_response)
    response=requests.request("PUT",update_url,headers=jira_headers,data=payload,auth=("<jira_api_user_emailID>","<jira_api_token>"))
    # data=response.json()
    # print(data)
  return None

def moderate_lambda_handler(event, context):
  data = {}
  with open('MODERATE.csv', encoding='utf-8') as csvf:
    csvReader = csv.DictReader(csvf)
    for rows in csvReader:
      key = rows['securityVulnerability__package__name']
      data[key] = rows
  # print(type(data))
  final_data = {}
  for key in data.keys():
    final_data[key] = data[key]['securityVulnerability__vulnerableVersionRange']
    
  vuln_mapping = "\n".join([f"{key}: {value}" for key,value in final_data.items()])  
    
  data_result = "Security vulnerability issues found in project - %s - MODERATE" % args.repository
  hash_object = hashlib.sha256(data_result.encode('utf-8'))
  hash_key = hash_object.hexdigest()
  # print(hash_key)

  search_item = {'ID': hash_key}
  item_response = DYNAMODB_TABLE.get_item(Key={'ID': hash_key})
  if 'Item' not in item_response:
      moderate_payload=json.dumps(
        {
          "fields": {
            "project":
            {
              "key": "WSH"
            },
            "summary": "Security vulnerability issues found in project - %s - MODERATE" % args.repository,
            "description": "Following are the and list of vulnerabilities found for the above project: \n {code:bash}%s{code}\n Please access security alerts from here: [Dependabot URL | https://github.com/<org_name>/%s/security/dependabot]" % (vuln_mapping,args.repository), 
            "issuetype": {
                "name": "Bug"
            },
            "priority": {
              "name": "P2"
            }
          }
        }
      )
      # print(payload)
      url = "https://<org_name>.atlassian.net/rest/api/2/issue"
      response=requests.post(url,headers=jira_headers,data=moderate_payload,auth=("<jira_api_user_emailID>","<jira_api_token>"))
      data=response.json()
      print(data)
      item = {
          'ID': hash_key,
          'KEY': data['key']
          # 'TTL': int(time.time()) + 2419200
      }
      DYNAMODB_TABLE.put_item(Item=item)
  else:
    item = item_response.get('Item')
    item_key_response = item.get('KEY')
    print(item_key_response)
    payload = json.dumps({
        "update": {
            "description": [
              {
                "set": "Following are the and list of vulnerabilities found for the above project: \n {code:bash}%s{code}\n Please access security alerts from here: [Dependabot URL | https://github.com/<org_name>/%s/security/dependabot]" % (vuln_mapping,args.repository)
              }
            ]
        }
    }
    )
    update_url = "https://<org_name>.atlassian.net/rest/api/2/issue/%s" % (item_key_response)
    response=requests.request("PUT",update_url,headers=jira_headers,data=payload,auth=("<jira_api_user_emailID>","<jira_api_token>"))
    # data=response.json()
    # print(data)
  return None

def low_lambda_handler(event, context):
  data = {}
  with open('LOW.csv', encoding='utf-8') as csvf:
    csvReader = csv.DictReader(csvf)
    for rows in csvReader:
      key = rows['securityVulnerability__package__name']
      data[key] = rows
  # print(type(data))
  final_data = {}
  for key in data.keys():
    final_data[key] = data[key]['securityVulnerability__vulnerableVersionRange']
    
  vuln_mapping = "\n".join([f"{key}: {value}" for key,value in final_data.items()])  
    
  data_result = "Security vulnerability issues found in project - %s - LOW" % args.repository
  hash_object = hashlib.sha256(data_result.encode('utf-8'))
  hash_key = hash_object.hexdigest()
  # print(hash_key)

  search_item = {'ID': hash_key}
  item_response = DYNAMODB_TABLE.get_item(Key={'ID': hash_key})
  if 'Item' not in item_response:
      low_payload=json.dumps(
        {
          "fields": {
            "project":
            {
              "key": "WSH"
            },
            "summary": "Security vulnerability issues found in project - %s - LOW" % args.repository,
            "description": "Following are the and list of vulnerabilities found for the above project: \n {code:bash}%s{code}\n Please access security alerts from here: [Dependabot URL | https://github.com/<org_name>/%s/security/dependabot]" % (vuln_mapping,args.repository), 
            "issuetype": {
                "name": "Bug"
            },
            "priority": {
              "name": "P3"
            }
          }
        }
      )
      # print(payload)
      url = "https://<org_name>.atlassian.net/rest/api/2/issue"
      response=requests.post(url,headers=jira_headers,data=low_payload,auth=("<jira_api_user_emailID>","<jira_api_token>"))
      data=response.json()
      print(data)
      item = {
          'ID': hash_key,
          'KEY': data['key']
          # 'TTL': int(time.time()) + 2419200
      }
      DYNAMODB_TABLE.put_item(Item=item)
  else:
    item = item_response.get('Item')
    item_key_response = item.get('KEY')
    print(item_key_response)
    payload = json.dumps({
        "update": {
            "description": [
              {
                "set": "Following are the and list of vulnerabilities found for the above project: \n {code:bash}%s{code}\n Please access security alerts from here: [Dependabot URL | https://github.com/<org_name>/%s/security/dependabot]" % (vuln_mapping,args.repository)
              }
            ]
        }
    }
    )
    update_url = "https://<org_name>.atlassian.net/rest/api/2/issue/%s" % (item_key_response)
    response=requests.request("PUT",update_url,headers=jira_headers,data=payload,auth=("<jira_api_user_emailID>","<jira_api_token>"))
    # data=response.json()
    # print(data)
  return None

if __name__ == "__main__":
    event = []
    context = []
    critical_lambda_handler(event, context)
    high_lambda_handler(event, context)
    moderate_lambda_handler(event, context)
    low_lambda_handler(event, context)
