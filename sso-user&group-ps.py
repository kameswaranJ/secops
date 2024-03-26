import boto3
import csv
import json
import string
import time
import unicodedata
import os
import botocore
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

os.environ['AWS_PROFILE'] = "500631996429_ps-cloud-secops-adm"

def list_accounts():
    account_list = []
    org = boto3.client('organizations', region_name="us-east-1")
    paginator = org.get_paginator('list_accounts')
    page_iterator = paginator.paginate()

    for page in page_iterator:
        for acct in page['Accounts']:
            if acct['Status'] == 'ACTIVE':
                account_list.append({'name': acct['Name'], 'id': acct['Id']})

    return account_list

def list_existing_sso_instances():
    client = boto3.client('sso-admin', region_name="us-east-1")
    sso_instance_list = []
    response = client.list_instances()
    for sso_instance in response['Instances']:
        sso_instance_list.append({'instanceArn': sso_instance["InstanceArn"], 'identityStore': sso_instance["IdentityStoreId"]})
    return sso_instance_list

def list_permission_sets(ssoInstanceArn):
    client = boto3.client('sso-admin', region_name="us-east-1")
    perm_set_dict = {}
    response = client.list_permission_sets(InstanceArn=ssoInstanceArn)
    results = response["PermissionSets"]
    while "NextToken" in response:
        response = client.list_permission_sets(InstanceArn=ssoInstanceArn, NextToken=response["NextToken"])
        results.extend(response["PermissionSets"])

    for permission_set in results:
        perm_description = client.describe_permission_set(InstanceArn=ssoInstanceArn, PermissionSetArn=permission_set)
        perm_set_dict[perm_description["PermissionSet"]["Name"]] = permission_set

    return perm_set_dict

def list_account_assignments(ssoInstanceArn, accountId, permissionSetArn):
    client = boto3.client('sso-admin', region_name="us-east-1")
    paginator = client.get_paginator("list_account_assignments")
    response_iterator = paginator.paginate(
        InstanceArn=ssoInstanceArn,
        AccountId=accountId,
        PermissionSetArn=permissionSetArn
    )

    account_assignments = []
    for response in response_iterator:
        for row in response['AccountAssignments']:
            account_assignments.append({'PrincipalType': row['PrincipalType'], 'PrincipalId': row['PrincipalId']})

    return account_assignments

def describe_user(userId, identityStoreId):
    client = boto3.client('identitystore', region_name="us-east-1")
    try:
        response = client.describe_user(
            IdentityStoreId=identityStoreId,
            UserId=userId
        )
        username = response['UserName']
        return username
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"User with ID {userId} not found.")
            return f"UnknownUser-{userId}"
        else:
            print(f"Error occurred: {e}")
            return None

def describe_group(groupId, identityStoreId):
    client = boto3.client('identitystore', region_name="us-east-1")
    try:
        response = client.describe_group(
            IdentityStoreId=identityStoreId,
            GroupId=groupId
        )
        groupname = response['DisplayName']
        return groupname
    except Exception as e:
        print("[WARN] Group was deleted while the report was running: " + str(groupId))
        groupname = "DELETED-GROUP"
        return groupname

def write_result_to_file(result):
    filename = 'sso_report_Account_Assignments_' + datetime.now().strftime("%Y-%m-%d_%H.%M.%S") + '.csv'
    filename = clean_filename(filename)
    with open(filename, 'w', newline='') as csv_file:
        fieldnames = ['AccountID', 'AccountName', 'ObjectType', 'ObjectName', 'PermissionSet']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for row in result:
            writer.writerow(row)

def print_time_taken(start, end):
    elapsed_time = end - start
    elapsed_time_string = str(int(elapsed_time / 60)) + " minutes and " + str(int(elapsed_time % 60)) + " seconds"
    print("The report took " + elapsed_time_string + " to generate.")

def clean_filename(filename, replace=' ', char_limit=255):
    valid_filename_chars = "-_.() %s%s" % (string.ascii_letters, string.digits)
    for r in replace:
        filename = filename.replace(r, '_')
    cleaned_filename = unicodedata.normalize('NFKD', filename).encode('ASCII', 'ignore').decode()
    cleaned_filename = ''.join(c for c in cleaned_filename if c in valid_filename_chars)
    if len(cleaned_filename) > char_limit:
        print("Warning, filename truncated because it was over {}. Filenames may no longer be unique".format(char_limit))
    return cleaned_filename[:char_limit]

def process_account(account_id, account_list, sso_instance, permission_sets_list):
    result = []

    account = next((acc for acc in account_list if acc['id'] == account_id), None)
    if account:
        print(f'Processing Account: {account}')
        for permission_set in permission_sets_list.keys():
            account_assignments = list_account_assignments(sso_instance['instanceArn'], account_id, permission_sets_list[permission_set])
            for account_assignment in account_assignments:
                account_assignments_dic = {}
                account_assignments_dic['AccountID'] = f"'{account_id}"  # Ensure account ID is formatted as text
                account_assignments_dic['AccountName'] = account['name']
                account_assignments_dic['PermissionSet'] = permission_set
                account_assignments_dic['ObjectType'] = account_assignment['PrincipalType']
                if account_assignments_dic['ObjectType'] == "USER":
                    username = describe_user(account_assignment['PrincipalId'], sso_instance['identityStore'])
                    account_assignments_dic['ObjectName'] = username
                elif account_assignments_dic['ObjectType'] == "GROUP":
                    groupname = describe_group(account_assignment['PrincipalId'], sso_instance['identityStore'])
                    account_assignments_dic['ObjectName'] = groupname
                result.append(account_assignments_dic)

        print(f"Finished processing Account: {account}")
    return result

def create_report(account_list, sso_instance, permission_sets_list):
    result = []

    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(process_account, account['id'], account_list, sso_instance, permission_sets_list) for account in account_list]
        for future in futures:
            result.extend(future.result())

    return result

def main():
    start = time.time()
    account_list = list_accounts()
    sso_instance = list_existing_sso_instances()[0]
    permission_sets_list = list_permission_sets(sso_instance['instanceArn'])
    result = create_report(account_list, sso_instance, permission_sets_list)
    write_result_to_file(result)
    end = time.time()
    print_time_taken(start, end)

if __name__ == "__main__":
    main()
