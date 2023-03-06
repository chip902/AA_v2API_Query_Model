import jwt
import requests
import time
import os
import csv
import json
import configparser
import logging
import datetime
import pandas as pd
import glob

private_key = 'private.key'
report_suite_id = 'monsbcsglobalprod'
api_version = '2.0'
global_company_id = 'monsan3'

pd.set_option('display.max_rows', None)
logging.basicConfig(level="INFO")
logger = logging.getLogger()

def get_jwt_token(config):
    with open(config["key_path"], 'r') as file:
        private_key = file.read()

    return jwt.encode({
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=30),
        "iss": config["orgid"],
        "sub": config["technicalaccountid"],
        "https://{}/s/{}".format(config["imshost"], config["metascopes"]): True,
        "aud": "https://{}/c/{}".format(config["imshost"], config["apikey"])
    }, private_key, algorithm='RS256')

def get_access_token(config, jwt_token):
    post_body = {
        "client_id": config["apikey"],
        "client_secret": config["secret"],
        "jwt_token": jwt_token
    }

    response = requests.post(config["imsexchange"], data=post_body)
    return response.json()["access_token"]

def get_first_global_company_id(config, access_token):
    response = requests.get(
        config["discoveryurl"],
        headers={
            "Authorization": "Bearer {}".format(access_token),
            "x-api-key": config["apikey"]
        }
    )

    # Return the first global company id
    return response.json().get("imsOrgs")[0].get("companies")[0].get("globalCompanyId")

config_parser = configparser.ConfigParser()
config_parser.read("config.ini")

config = dict(config_parser["default"])
jwt_token = get_jwt_token(config)
access_token = get_access_token(config, jwt_token)
global_company_id = get_first_global_company_id(config, access_token)
logger.info("global_company_id: {}".format(global_company_id))

url = f'https://analytics.adobe.io/api/{global_company_id}/reports'

headers = {
    'Authorization': f'Bearer {access_token}',
    'x-api-key': config["apikey"],
    'x-proxy-global-company-id': global_company_id,
    'x-proxy-use-session': 'true',
    'Content-Type': 'application/json'
}

json_queries = glob.glob('*.json')
results = []
for query_path in json_queries:
    # Load the query JSON
    with open(query_path, 'r') as f:
        query = json.load(f)

    response = requests.post(url, headers=headers, json=query)
    try:
        data = response.json()
        headers = [col['id'] for col in data['columns']]
        rows = []
        for row in data['rows']:
            rows.append(row['data'])
        df = pd.DataFrame(rows, columns=headers)
        results.append(df)
    except Exception as e:
        print(f"Error parsing response from query {query}: {e}")
        print(f"Response: {response.text}")

# Concatenate the data frames
result_df = pd.concat(results)

# Export the data frame to a CSV file
result_df.to_csv('result.csv', index=False)
