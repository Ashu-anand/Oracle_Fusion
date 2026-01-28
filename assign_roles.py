'''
Date            Ver     Description
-----------     ----    -------------------------------------------------------
29-Mar-2025     0.00    Added the Change Management
29-Mar-2025     0.01    Added the logging information
27-Jan-2026     0.02    refactoring the code to create a class for OracleFusionAccessManager
'''

import requests
import json as j
from common.utils import generate_basic_auth_token,convert_dict
from collections import defaultdict
import pandas as pd
import csv
import yaml
import sys
import os
import logging
import urllib3
#urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from urllib3.exceptions import InsecureRequestWarning
#requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger=logging.getLogger(__name__)

class OracleFusionAccessManager:
    def __init__(self, 
                 config_path,
                 file_name,
                 allow_interactive=False
                 ):
        logger.info("Class initialized")
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

        logger.info("Generating Token for the API call")
        self.token:str =generate_basic_auth_token(self.username,self.password)

        
        """self.session = requests.Session()
        self.session.headers.update({
            'Authorization': self.token,
            'Content-Type': 'application/vnd.oracle.adf.batch+json',
            'Accept': 'application/json'
        })
        """

    def load_config(self,config_path):
        logger.debug(f"Loading config from {config_path}")
        try:
            with open(config_path,"r") as f:
                config=yaml.safe_load(f).get("oracle_fusion",{})
                config_data={key:config.get(key) for key in ["instance_code", "instance_name", "username", "password"]}
            logger.info("Config file loaded successfully.")
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
        logger.info(f"Reading CSV file: {self.file_name}")
        try:
            df=pd.read_csv(file_name,dtype={"UserName":str})
            df.sort_values(by=["UserName"],inplace=True)
            logger.info("CSV file read successfully.")
            return df
        except FileNotFoundError:
            logger.error(f"CSV file {self.file_name} not found.")
            raise


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s- %(levelname)s - %(message)s')
    logger.info("Starting script execution.")
    
    # Get the directory where the current script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "config", "config.yaml")
    file_name='User_Data_Access.csv'
    assign_role=OracleFusionAccessManager(config_path,file_name,allow_interactive=True)
    assign_role.read_csv()
