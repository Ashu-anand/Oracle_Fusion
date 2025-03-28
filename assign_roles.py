import requests as r
import json as j
from common.utils import generate_basic_auth_token,convert_dict
from collections import defaultdict
import csv
import yaml

def create_output_list(result):
    final_list={}
    final_list=defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for val in result.json().get('items'):
        User=val['Userrf']
        Role=val['Rolerf']
        context=val['SecurityContext']
        contextvalue=val['SecurityContextValue']
        final_list[User][Role][context].append(contextvalue)
    #final_list = j.dumps(final_list, indent=4)

    return final_list


def create_payload(file_name:str=None):
    '''
    Adding Data Access to the users
    '''
    if file_name is not None:
        with open(file_name,'r',encoding='utf-8-sig',newline='') as file_obj:
            reader=csv.reader(file_obj)
            next(reader)
            payload = {
                "parts": [
                    {
                        "id": f"part{i+1}",
                        "path": "/dataSecurities",
                        "operation": "create",
                        "payload": {
                            "SecurityContext": Security_Context,
                            "SecurityContextValue": security_value,
                            "RoleNameCr": Role_NameCr,
                            "UserName": username
                        }
                    }
                    for i,(username,Security_Context,Role_NameCr,security_value) in enumerate(reader)
                ]
            }
    else:
        payload={}
    return payload


def fetch_data_access(base_url:str , 
                       base_uri:str,
                       p_token:str,
                       query_para:str='',
                       file_name:str=None                       
                       )-> dict:
    if query_para!='':
        query_para=f'?totalResults=true&{query_para}'
    else:
        query_para=f'?totalResults=true'
    call_url=f"{base_url}{base_uri}{query_para}"
    
    headers={
        #'Content-Type': 'application/vnd.oracle.adf.batch+json',
        'Authorization' :   p_token
    }
    json_payload = j.dumps(create_payload(file_name), indent=4)    
    response=r.request("GET",call_url,headers=headers,data=json_payload, verify=False,timeout=30,stream=False)
    
    return response


def check_hierarchy(data, user, role, security_context, value):
    """
    Checks if a given user has a specific role, security context, and value.

    :param data: The transformed dictionary from JSON response
    :param user: The user ID to check (e.g., "9999")
    :param role: The role to check (e.g., "Role 3")
    :param security_context: The security context to check (e.g., "Business Unit")
    :param value: The security context value to check (e.g., "USA")
    :return: True if all conditions exist, False otherwise
    """
    return (
        user in data and 
        role in data[user] and 
        security_context in data[user][role] and 
        value in data[user][role][security_context]
    )


def create_role_list(BASE_URL : str,
                     URI_PATH : str,
                     token    : str,
                     file_username:str):
    hasMore=True
    totalResults=0
    runningTotal=0
    
    result=fetch_data_access(BASE_URL,URI_PATH,token,f'q=Userrf={file_username}&offset={runningTotal}')
    list_of_roles=create_output_list(result)
    runningTotal=runningTotal + result.json().get('count')+1
    hasMore=result.json().get('hasMore')

    while hasMore:    
        result=fetch_data_access(BASE_URL,URI_PATH,token,f'q=Userrf={file_username}&offset={runningTotal}')
        hasMore=result.json().get('hasMore')
        runningTotal=runningTotal + result.json().get('count')+1

        list_of_roles[file_username].update(create_output_list(result)[file_username])
        if result.status_code==200 and hasMore:
            print('Yes')

    return convert_dict(list_of_roles)


instance_code=input("Enter Instance Code")
instance_name=input("Enter Instance Name")
username=input("Enter Username")
password=input("Enter Password")
token=generate_basic_auth_token(username,password)
list_of_roles={}

BASE_URL=f'https://{instance_code}-{instance_name}-saasfaprod1.fa.ocs.oraclecloud.com'
URI_PATH=f'/fscmRestApi/resources/11.13.18.05/dataSecurities'

file_name='User_Data_Access.csv'
import pandas as pd
df=pd.read_csv(file_name,dtype={"UserName":str})
df.sort_values(by=["UserName"],inplace=True)
for file_username in df["UserName"].unique():
    list_of_roles=create_role_list(BASE_URL, URI_PATH, token, file_username)


with open('Output.csv','w',encoding='utf-8-sig') as file_obj:
    file_obj.writelines("UserName, RoleName, SecurityContext, Value, Status\n")
    for index,row in df.iterrows():
        uname=row["UserName"]
        rolename=row["RoleNameCr"]
        security_context=row["SecurityContext"]
        value=row["SecurityContextValue"]
        if check_hierarchy(list_of_roles, uname, rolename, security_context, value):
            file_obj.writelines(f"{uname}, {rolename}, {security_context}, {value}, Access already assigned\n")
        else:
            file_obj.writelines(f"{uname}, {rolename}, {security_context}, {value}, Value not assigned\n")