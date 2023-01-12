################################################################################
### Copyright (C) 2019-2022 VMware, Inc.  All rights reserved.
### SPDX-License-Identifier: BSD-2-Clause
################################################################################
### By Bill Roth broth@vmware.com 1/6/2023
###
### Usage: python cluster-rename.py [org uuid] [sddc uid] [new name string]
### likely has python3 (3.7+) dependencies

import requests
import sys
import json

login_server = "https://console.cloud.vmware.com/csp/gateway" #replace these with yours. 
api_server = "http://vmc.vmware.com"
#
# return key from local file key.txt so it does not show up in code
#
def get_api_key():
    """Pull key from file so I dont have to include it in the code
       key.txt is a file with the API token in it, no spaces, or newlines.
    """
    keytext = ''
    try:
        with open('key.txt', mode='r') as file_object:
            keytext = file_object.readline()
    except FileNotFoundError:
        msg = "Sorry, the file key.txt does not exist. You must have a key.txt file with your API code in it in order to run this sample"
        print(msg) # Sorry, the file key.txt does not exist....
        exit(1)
 
    return keytext

def vmc_login():
    """Login to VMC on AWS with previously acquired API Key"""
    #
    # Pull the Auth API Key from a file (so I don't have to store it in the code)
    #
    key = get_api_key()
    url = f'{login_server}/am/api/auth/api-tokens/authorize'
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    payload = {'api_token': key}
    r = requests.post(f'{url}', headers=headers, params=payload)
    if r.status_code != 200:
        print(f'Unsuccessful Login Attempt. Error code {r.status_code}')
        exit()
    else:
       auth_json = r.json()['access_token']
       auth_Header = {'Content-Type': 'application/json','csp-auth-token': auth_json}
       return auth_Header

def printJsonObject(jobs) -> None:
    for i in jobs:
       print(f"{i} : {jobs[i]}")
    return

def cluster_rename(auth_header, org_id, cluster_id, new_name):
    url = f"{api_server}/api/inventory/{org_id}/vmc-aws/clusters/{cluster_id}:rename-cluster"
    headers = {'Content-Type': 'application/json', 
               'Accept' : 'application/json',
               'csp-auth-token' : auth_header['csp-auth-token']
               }

    rawdata = json.dumps({"cluster_name" : new_name})

    response = requests.post(url, headers=headers, data=rawdata)
    if response.status_code not in (200,202):
        print(f"Error: {response.status_code} returned from cluster rename. Text: {response.text}")
        sys.exit(1)
    else:
        json_response = response.json()
        print(json.dumps(json_response, indent=4))
    return
#
# Use this to pull the full information from the SDDC, and pull the first cluster listed.
#
def get_sddc_info(auth_header, org_id, sddc_id,print):
    '''Use this to pull the full information from the SDDC, and pull the first cluster listed.'''

    url = f"{api_server}/vmc/api/orgs/{org_id}/sddcs/{sddc_id}"
    headers = {'Content-Type': 'application/json', 
               'Accept' : 'application/json',
               'csp-auth-token' : auth_header['csp-auth-token'],
               'Accept-Encoding' : 'gzip, deflate'
               }
    response = requests.get(url, headers=headers)
    if response.status_code not in (200,202):
        print(f"Error: {response.status_code} returned from cluster rename. Text: {response.text}")
        sys.exit(1)
    else:
        json_response = response.json()
        if print:
            printJsonObject(json_response)
    #   print(json.dumps(json_response, indent=4))
        return json_response['resource_config']['clusters'][0]['cluster_id']
#
# Main Code
#
def main():
    auth_header = vmc_login()
    if len(sys.argv) != 4:
        print("Bad args")
        sys.exit(1)

    org_id = sys.argv[1]
    sddc_id = sys.argv[2]
    new_name = sys.argv[3]
    cluster_uuid = get_sddc_info(auth_header, org_id, sddc_id, True)
    cluster_rename(auth_header, org_id, cluster_uuid,new_name)

if __name__ == "__main__":
    main()

