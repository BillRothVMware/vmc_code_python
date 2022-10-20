#
# Make sure to erase the token
# make sure to lintify when ready for publication.

import requests
import os
import json
import time
from prettytable import PrettyTable

debug = True

#
# retun key from local file key.txt so it does not show up in code
#
def get_api_key() -> str:
    """Pull key from file so I dont have to include it in the code"""
    keytext = ''
    try:
        with open('key.txt', mode='r') as file_object:
            keytext = file_object.readline()
    except FileNotFoundError:
        msg = "Sorry, the file key.txt does not exist. You must have a key.txt file with your API code in it in order to run this sample"
        print(msg) # Sorry, the file key.txt does not exist....
        exit()

    return keytext

#
# from https://developer.vmware.com/apis/vmc/latest/
#
def vmc_login():
    """Login to VMC on AWS with previously acquired API Key"""
    #
    # Pull the Auth API Key from a file (so I don't have to store it in the code)
    #
    key = get_api_key()
    url = 'https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize'
    headers = {'Content-Type': 'application/json'}
    payload = {'refresh_token': key}
    r = requests.post(f'{url}', headers=headers, params=payload)
    if r.status_code != 200:
        print(f'Unsuccessful Login Attempt. Error code {r.status_code}')
        exit()
    else:
        auth_json = r.json()['access_token']
        if debug: 
            print (f'Auth COde is {auth_json}')
        auth_Header = {'Content-Type': 'application/json',
                       'csp-auth-token': auth_json}
        return auth_Header
#
# We get he connected account so we can get he VPC and the subnetss, which are owned by the
# unterlying AWS resources.
#

def get_connected_account(orgId, header):
    resp = requests.get(
        f'https://vmc.vmware.com/vmc/api/orgs/{orgId}/account-link/connected-accounts', headers=header)
    if resp.status_code != 200:
        print(f'error in connected account {resp.status_code} for org {orgId}')
        exit()
    results = json.loads(resp.text)
    print("\nConnected Accounts")
    accounts_table = PrettyTable(["ID", "Account Number", "User Name"])
    for cId in results:
        # print("ID:" + cId['id'] + " Account number:" + cId['account_number']  + " User Name:"+ cId['user_name'])
        accounts_table.add_row([cId['id'],cId['account_number'],cId['user_name']])
        
    print(accounts_table)

    connected_account = results[0]['id']
    if debug: 
        print(f'Connected account is {connected_account}')
    return connected_account
#
# Get subnet ID
# Doc string: https://developer.vmware.com/apis/vmc/latest/vmc/api/orgs/org/account-link/compatible-subnets/get/ 
#  
def get_compatible_subnet_id(orgId, header, linkedAccount, region):
    """get the first applicable compatible subnet"""

    urlParams = {'linkedAccountId' : linkedAccount,
                'region' : region}
    resp = requests.get(f'https://vmc.vmware.com/vmc/api/orgs/{orgId}/account-link/compatible-subnets',
        params=urlParams,
        headers=header)
    if resp.status_code != 200:
        print(f'\nError when getting compatible subnets {resp.status_code} : {resp.reason} with acct {linkedAccount} for org {orgId} in region {region}.')
        return None

    results = json.loads(resp.text)
    subnets = results['vpc_map']
    #
    # In my case, pull the name of the default VPC, since I know the subnets work for this
    #
    subnet_table = PrettyTable(["ID", "Description","CIDR Block","Subnet 0","Num Subnets","0 Compatible"])
    print("\nSubnet Table")
    for key in subnets:
        subnet_table.add_row([key,subnets[key]['description'],subnets[key]['cidr_block'],subnets[key]['subnets'][0]['subnet_id'],len(subnets[key]['subnets']),
            subnets[key]['subnets'][0]['compatible']])

    print(subnet_table)
    #
    # Pull the first subnet
    #
    firstkey = list(subnets.keys())[0]
    fullsubnet = subnets[firstkey]['subnets']
    subnetID = fullsubnet[0]['subnet_id']
    if debug:
        print(f"compatible_subnet is {subnetID}")
    return subnetID

#
#  Create the SDDC: https://developer.vmware.com/apis/vmc/latest/vmc/api/orgs/org/sddcs/post/
# 
def create_sddc(header, org, name, provider, region, numHost, connectedAccount, subnetId, ValidateOnly):

    if subnetId == None:
        print("Error: Can Not Get Valid SubnetID")
        exit()

    data = {
        'name': name,
        'account_link_sddc_config': [
            {
                'customer_subnet_ids': [
                    subnetId
                ],
                'connected_account_id': connectedAccount
            }
        ],
        'provider': provider.upper(),   # make sure provider is in upper case
        'num_hosts': numHost,           # 1 host in this case
        'sddc_type': '1NODE',
        'region': region                # region where we have permissions to deploy.
    }

    resp = requests.post(
        f'https://vmc.vmware.com/vmc/api/orgs/{org}/sddcs', json=data, headers=header)
    json_response = resp.json()
    print(name + ' SDDC ' + str(json_response['status']))
 
    if resp.status_code in (200,202):
        print('Status Code= ' + str(resp.status_code))
        newTask = json_response['id']
        if debug:
            print(f'New Task = {newTask}')
        return newTask
    else:
        if "error_messages" in json_response.keys():
            print(f'Error on create {json_response["error_messages"]}')
        else:
            print("Error on create")
        exit()
#
#
def poll_sddc_until_created(orgID, newtask, header):
    notDone = True
    while notDone:
        resp = requests.get(
            f'https://vmc.vmware.com/vmc/api/orgs/{orgID}/tasks/{newtask}', headers=header)
        
        parsed = resp.json()

        if resp.status_code != 200:
            if resp.status_code == 401:  #HERE
                print("401 error code")
            if "error_messages" in parsed.keys():
                print(f'Error on create {parsed["error_messages"]}')
            else:
                print("Error on create")
            return False

        print("Status Code = " + str(resp.status_code))
        print("Resp Status " + parsed['status']) # check for numeric
        print("Resp SubStatus " + parsed['sub_status'])

        if parsed['status'] == "FAILED":
            notDone = False
            if 'resource_id' in parsed.keys():
                sddcID = parsed['resource_id']
                print("Failed SDDC ID is " + sddcID)

            print("error Message: " + parsed['error_message'])
            if 'params' in parsed:
                print("SDDC Params" + str(parsed['params']))
            return False
        time.sleep(15)  # 15 seconds, so we dont hammer the server
    return True 
#
# Method to delete SDDC once created, if you have permissions and the right IDs. BE CAREFUL
#
def delete_sddc(header, orgID, sddcID):
    resp = requests.delete(
        f'https://vmc.vmware.com/vmc/api/orgs/{orgID}/sddcs/{sddcID}', 
            headers=header)
    if resp.status_code not in (200, 202):
        return False

    json_response = resp.json()
    return json_response

#
# Pull info from the SDDC
#
def get_sddc_info(token, orgID, sddcID):
    headers = {'csp-auth-token': token, 'Content-Type': 'application/json'}
    resp = requests.get(
        f'https://vmc.vmware.com/vmc/api/orgs/{orgID}/sddcs/{sddcID}', headers=headers)
    if resp.status_code != 200:
        return False

    json_response = resp.json()
    return 1
#
# Pull an sddc template. https://developer.vmware.com/apis/vmc/latest/vmc/api/orgs/org/sddcs/sddc/sddc-template/get/
#
def get_sddc_template(header,orgID,sddcID):

    resp = requests.get(
        f'https://vmc.vmware.com/vmc/api/orgs/{orgID}/sddcs/{sddcID}/sddc-template', headers=header)
    if resp.status_code != 200:
        return False

    json_response = resp.json()
    return json_response
#
# Docs: https://developer.vmware.com/apis/vmc/latest/vmc/api/orgs/org/sddcs/get/
#
def list_sddcs(auth_header,orgID):
    """print a list of SDDCs"""
    sddcList = requests.get(
        f'https://vmc.vmware.com/vmc/api/orgs/{orgID}/sddcs', headers=auth_header)
    if sddcList.status_code != 200:
        print(f'API Error {sddcList.status_code} : {sddcList.reason}')
        print(sddcList)
        exit(1)
    else:
        for sddc in sddcList.json():
            print("SDDC Name: " + sddc['name'])
            print("SDDC id: " + sddc['id'])
            print("SDDC Create Date: " + sddc['created'])
            print("SDDC Provider: " + sddc['provider'])
            print("SDDC Region: " + sddc['resource_config']['region'])
            print()
#
# Docs: https://developer.vmware.com/apis/vmc/latest/vmc/api/orgs/get/
#
def get_organization(auth_header, org_name):
    """Pull a list of organizations, and return one to work on for new SDDC"""

    orgList = requests.get(
        'https://vmc.vmware.com/vmc/api/orgs', headers=auth_header)
#
# Scan the list of Orgs and pick the Org we want to create an SDDC in from the list. 
#
    x=0

    for org1 in orgList.json():
        print('Num ', x,  org1['id'],
              'Display Name ', org1['display_name'], "user", org1['user_name'])
             
        if org1['display_name'] == org_name:
            break
        x += 1
    
    if x == len(orgList.json()):
        print("Org Not Found")
        exit(1)
#
# Return Info about Org
#
    orgID = orgList.json()[x]['id']
    return orgID
#
# main
#
def main():
    auth_header = vmc_login()
    if auth_header != None:
        print(f'Auth header received')
    else:
        print(f'getting auth header failed')
        exit(1)
    
    orgID = get_organization(auth_header,"VMC-SET-PYTHON")
    list_sddcs(auth_header, orgID)
    connectedAccount = get_connected_account(orgID, auth_header)
    region = "US_WEST_2"
    compat_subnet = get_compatible_subnet_id(orgID, auth_header,connectedAccount, region)

    createTask = create_sddc(auth_header, orgID, "RothTest2", "AWS", region, 1, connectedAccount,compat_subnet, False)

# Poll until done
    sddcPollResult = poll_sddc_until_created(orgID, createTask, auth_header)

    if sddcPollResult == False:
        print("Failed. Exiting")
        exit(1)
    else:
        exit(0)

if __name__ == "__main__":
    main()
