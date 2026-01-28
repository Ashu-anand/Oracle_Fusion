'''
Date            Ver     Description
-----------     ----    -------------------------------------------------------
29-Mar-2025     0.00    Added the Change Management
29-Mar-2025     0.01    Added the logging information
27-Jan-2026     0.02    refactoring the code to create a class for OracleFusionAccessManager
TODO: 
1) Remove trailing spaces from the names
2) Add Role Assignment
'''
import requests
import json as j
from common.utils import generate_basic_auth_token,convert_dict
from collections import defaultdict
from typing import Optional
import pandas as pd
import yaml
import os
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


logger=logging.getLogger(__name__)

class OracleFusionAccessManager:
    def __init__(self, 
                 config_path,
                 file_name,
                 allow_interactive=False
                 ):
        logger.debug("Class initialized")
        logger.info("Loading configuration data")
        self.allow_interactive=allow_interactive
        self.config_data=self.load_config(config_path)
        self.file_name=file_name
        self.instance_code, self.instance_name, self.username, self.password = (
            self.config_data["instance_code"],
            self.config_data["instance_name"],
            self.config_data["username"],
            self.config_data["password"]
            )
        
        self.base_url: str  = f'https://{self.instance_code}-{self.instance_name}-saasfaprod1.fa.ocs.oraclecloud.com'
        self.uri_path: str  = f'/fscmRestApi/resources/11.13.18.05/dataSecurities'
        self.assign_uri_path:str =f'/fscmRestApi/resources/latest'

        logger.debug("Generating Token for the API call")
        self.token:str =generate_basic_auth_token(self.username,self.password)

    def load_config(self,config_path):
        logger.debug(f"Loading config from {config_path}")
        try:
            with open(config_path,"r") as f:
                config=yaml.safe_load(f).get("oracle_fusion",{})
                config_data={key:config.get(key) for key in ["instance_code", "instance_name", "username", "password"]}
            logger.debug("Config file loaded successfully.")
        except FileNotFoundError:
            if self.allow_interactive:
                logger.warning("Config.yaml File not Found. Please enter the details manually.")
                config_data={}
                for key in ["instance_code", "instance_name", "username", "password"]:
                    config_data[key] = input(f"Enter {key.replace('_', ' ').title()}: ").strip()
            else:
                logger.error("Config.yaml File not Found.")
                raise
        return config_data
    
    def read_csv(self):
        logger.debug(f"Reading CSV file: {self.file_name}")
        try:
            self.df=pd.read_csv(self.file_name,dtype={"UserName":str})
            self.df.sort_values(by=["UserName"],inplace=True)
            logger.info("CSV file read successfully.")
            return self.df
        except FileNotFoundError:
            logger.error(f"CSV file {self.file_name} not found.")
            raise

    def user_has_access(self,data, user, role, security_context, value):
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

    def process_row(self):
        logger.info("Processing user data access")
        with open('Output.csv','w',encoding='utf-8-sig') as file_obj:
            file_obj.writelines("UserName, RoleName, SecurityContext, Value, Status\n")
            list_of_roles={}

            for file_username in self.df["UserName"].unique():
                reader=[]
                
                logger.info(f'Fetching existing access for {file_username}')

                list_of_roles=self.collect_user_roles(file_username)
                logger.info(f'Assigning Data Access for {file_username}')
                for index,row in self.df[self.df["UserName"]==file_username].iterrows():                    
                    uname=row["UserName"]
                    rolename=row["RoleNameCr"]
                    security_context=row["SecurityContext"]
                    value=row["SecurityContextValue"]
                    if self.user_has_access(list_of_roles, uname, rolename, security_context, value):
                        file_obj.writelines(f"{uname}, {rolename}, {security_context}, {value}, Access already assigned\n")
                    else:
                        reader.append((uname,security_context,rolename,value))
                        file_obj.writelines(f"{uname}, {rolename}, {security_context}, {value}, Value not assigned\n")
                if reader:
                    logger.info(f'Assigning new access for {file_username}')  
                    result=self.assign_data_access(reader)
                    if result and result.status_code==200:
                        logger.info(f'Data Access granted for {file_username}')
                    else:
                        logger.error(f"Failed to assign access for {file_username}: {result.text if result else 'No response'}")

    def create_api_payload(self, reader):
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

    def assign_data_access(self,
                        reader:list
                        )-> Optional[requests.Response]:
        
        url=f"{self.base_url}{self.assign_uri_path}"
        
        headers={
            'Content-Type': 'application/vnd.oracle.adf.batch+json',
            'Authorization' :   self.token
        }
        json_payload = j.dumps(self.create_api_payload(reader), indent=4)

        logger.info(f"Assigning data access for {len(reader)} records.")
        logger.debug(f"Payload: {json_payload}")
        try:
            response=requests.request("POST",url,headers=headers,data=json_payload, verify=False,timeout=30,stream=False)
            logger.debug(f"POST request sent. Status Code: {response.status_code}")
            return response
        except Exception as e:
            logger.error(f"Failed to assign data access: {e}")
            logger.error(f"Payload: {json_payload}")
            return None

    def collect_user_roles(self,
                        file_username:str):
        hasMore=True
        runningTotal=0
        list_of_roles = {}

        result=self.fetch_data_from_api(f'q=Userrf={file_username}&offset={runningTotal}')

        if result is None:
            logger.error(f"Failed to fetch data for user {file_username}")
            return {}

        list_of_roles=self.create_output_dict(result)
        runningTotal=runningTotal + result.json().get('count')+1
        hasMore=result.json().get('hasMore')

        while hasMore:    
            result=self.fetch_data_from_api(f'q=Userrf={file_username}&offset={runningTotal}')
            if result is None:
                logger.error(f"Failed to fetch data for user {file_username}")
                return {}
            
            hasMore=result.json().get('hasMore', False)
            runningTotal+= result.json().get('count',0)+1

            list_of_roles[file_username].update(self.create_output_dict(result)[file_username])

        return convert_dict(list_of_roles)

    def fetch_data_from_api(self,
                            query_para:str=''                      
                        )-> Optional[requests.Response]:
        
        query_para=f'?totalResults=true&{query_para}' if query_para else f'?totalResults=true'
        url=f"{self.base_url}{self.uri_path}{query_para}"

        headers={        
            'Authorization' :   self.token
        }

        logger.info(f"Making GET request to {url}")
        logger.debug(f"Headers: {headers}")

        try:
            response=requests.request("GET",url,headers=headers,data={}, verify=False,timeout=30,stream=False)
            if response.status_code==200:
                logger.info("API response received successfully.")
            else:
                logger.warning(f"API returned status {response.status_code}: {response.text}")
            return response
        except Exception as e:
            logger.error(f"Failed to fetch data: {e}")
            return None

    def create_output_dict(self,response):
        logger.debug("Transforming API response into structured dictionary.")
        result=defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        try:
            for val in response.json().get('items'):
                User=val['Userrf']
                Role=val['Rolerf']
                context=val['SecurityContext']
                contextvalue=val['SecurityContextValue']
                result[User][Role][context].append(contextvalue)
            logger.debug("Transformation successful.")
        except Exception as e:
            logger.error(f"Error in processing API response: {e}")
        return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s- %(levelname)s - %(message)s')
    logger.info("Starting script execution.")
    
    # Get the directory where the current script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "config", "config.yaml")
    file_name='User_Data_Access.csv'
    assign_role=OracleFusionAccessManager(config_path,file_name,allow_interactive=True)    
    assign_role.read_csv()
    assign_role.process_row()

