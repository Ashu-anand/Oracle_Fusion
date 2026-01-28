'''
Date            Ver     Description
-----------     ----    -------------------------------------------------------
29-Mar-2025     0.00    Added the Change Management
29-Mar-2025     0.01    Added the logging information
27-Jan-2026     0.02    
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
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from urllib3.exceptions import InsecureRequestWarning
#requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger=logging.getLogger(__name__)

class OracleFusionAccessManager:
    def __init__(self, 
                 base_url: str, 
                 uri_path: str, 
                 token: str
                 ):
        logger.info("Class initialized")
        self.base_url: str  = base_url
        self.uri_path: str  = uri_path
        self.token: str     = token
        
        """self.session = requests.Session()
        self.session.headers.update({
            'Authorization': self.token,
            'Content-Type': 'application/vnd.oracle.adf.batch+json',
            'Accept': 'application/json'
        })
        """
    
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
                            "SecurityContext"       : Security_Context,
                            "SecurityContextValue"  : security_value,
                            "RoleNameCr"            : Role_NameCr,
                            "UserName"              : username
                            }
                }
                    for i,(username,Security_Context,Role_NameCr,security_value) in enumerate(reader)
                ]
            }
        return payload

    def user_has_access(self, data, user, role, security_context, value):
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


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s- %(levelname)s - %(message)s')
    logger.info("Starting script execution.")
