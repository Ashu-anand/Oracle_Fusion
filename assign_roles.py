import requests as r
import json as j
from common.utils import generate_basic_auth_token,convert_dict
from collections import defaultdict
import pandas as pd
import csv
import yaml
import sys
import os
import logging

from urllib3.exceptions import InsecureRequestWarning
r.packages.urllib3.disable_warnings(InsecureRequestWarning)


logger=logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Get the directory where the current script is located
script_dir = os.path.dirname(os.path.abspath(__file__))

# Build the path to the config.yaml file relative to the script
config_path = os.path.join(script_dir, "config", "config.yaml")


def load_config(config_path):    
    try:
        with open(config_path,"r") as f:
            config=yaml.safe_load(f).get("oracle_fusion",{})
            config_data={key:config.get(key) for key in ["instance_code", "instance_name", "username", "password"]}

    except FileNotFoundError:
        #logger.info("Config.yaml File not Found. Please enter the details manually.")
        config_data={}
        for key in ["instance_code", "instance_name", "username", "password"]:
            config_data[key] = input(f"Enter {key.replace('_', ' ').title()}: ").strip()
    return config_data


def create_output_dict(response):
    result=defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for val in response.json().get('items'):
        User=val['Userrf']
        Role=val['Rolerf']
        context=val['SecurityContext']
        contextvalue=val['SecurityContextValue']
        result[User][Role][context].append(contextvalue)
    return result


def create_api_payload(reader):
    '''
    Adding Data Access to the users
    '''
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
    return payload


def assign_data_access(base_url:str , 
                       base_uri:str,
                       p_token:str,
                       reader:list
                       )-> dict:
    
    url=f"{base_url}{base_uri}"
    
    headers={
        'Content-Type': 'application/vnd.oracle.adf.batch+json',
        'Authorization' :   p_token
    }
    json_payload = j.dumps(create_api_payload(reader), indent=4)
    response=r.request("POST",url,headers=headers,data=json_payload, verify=False,timeout=30,stream=False)
    
    return response


def fetch_data_from_api(base_url:str , 
                       base_uri:str,
                       p_token:str,
                       query_para:str='',
                       file_name:str=None                       
                       )-> dict:
    
    query_para=f'?totalResults=true&{query_para}' if query_para else f'?totalResults=true'
    url=f"{base_url}{base_uri}{query_para}"
    
    headers={
        #'Content-Type': 'application/vnd.oracle.adf.batch+json',
        'Authorization' :   p_token
    }

    logger.debug(f'url : {url}')
    logger.debug(f'header : {headers}')

    response=r.request("GET",url,headers=headers,data={}, verify=False,timeout=30,stream=False)
    
    return response


def user_has_access(data, user, role, security_context, value):
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


def collect_user_roles(BASE_URL : str,
                       URI_PATH : str,
                       token    : str,
                       file_username:str):
    hasMore=True
    totalResults=0
    runningTotal=0
    list_of_roles = {}

    result=fetch_data_from_api(BASE_URL,URI_PATH,token,f'q=Userrf={file_username}&offset={runningTotal}')
    list_of_roles=create_output_dict(result)
    runningTotal=runningTotal + result.json().get('count')+1
    hasMore=result.json().get('hasMore')

    while hasMore:    
        result=fetch_data_from_api(BASE_URL,URI_PATH,token,f'q=Userrf={file_username}&offset={runningTotal}')
        hasMore=result.json().get('hasMore', False)
        runningTotal+= result.json().get('count',0)+1

        list_of_roles[file_username].update(create_output_dict(result)[file_username])

    return convert_dict(list_of_roles)


logger.info("Loading Config File")
config_data=load_config(config_path)
instance_code, instance_name, username, password = (
    config_data["instance_code"],
    config_data["instance_name"],
    config_data["username"],
    config_data["password"],
)

logger.info("Generating Token for the API call")
token=generate_basic_auth_token(username,password)

BASE_URL=f'https://{instance_code}-{instance_name}-saasfaprod1.fa.ocs.oraclecloud.com'
URI_PATH=f'/fscmRestApi/resources/11.13.18.05/dataSecurities'
ASSIGN_URI_PATH=f'/fscmRestApi/resources/latest'

file_name='User_Data_Access.csv'

logger.info("Reading Data file")
df=pd.read_csv(file_name,dtype={"UserName":str})
df.sort_values(by=["UserName"],inplace=True)

with open('Output.csv','w',encoding='utf-8-sig') as file_obj:
    file_obj.writelines("UserName, RoleName, SecurityContext, Value, Status\n")
    list_of_roles={}

    for file_username in df["UserName"].unique():
        reader=[]        
        logger.info(f'Fetching list for {file_username}')
        list_of_roles=collect_user_roles(BASE_URL, URI_PATH, token, file_username)

        logger.info(f'Assigning Data Access for {file_username}')
        for index,row in df[df["UserName"]==file_username].iterrows():
            uname=row["UserName"]
            rolename=row["RoleNameCr"]
            security_context=row["SecurityContext"]
            value=row["SecurityContextValue"]
            if user_has_access(list_of_roles, uname, rolename, security_context, value):
                file_obj.writelines(f"{uname}, {rolename}, {security_context}, {value}, Access already assigned\n")
            else:
                reader.append((uname,security_context,rolename,value))
                file_obj.writelines(f"{uname}, {rolename}, {security_context}, {value}, Value not assigned\n")

        if len(reader)!=0:            
            result=assign_data_access(BASE_URL, ASSIGN_URI_PATH, token, reader)
            if result.status_code==200:
                logger.info(f'Data Access granted for {file_username}')
            else:
                print(result.text)