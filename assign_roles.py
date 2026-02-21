"""Oracle Fusion bulk role assignment automation.

Automates the assignment of data security roles to users in Oracle Fusion Cloud
via REST APIs. Reads user-role mappings from CSV, checks existing access,
and performs batch assignments for missing roles.

Usage:
    python assign_roles.py

Configuration:
    Requires config/config.yaml with Oracle Fusion connection details.
"""
#Changelog:
#  Date            Ver     Description
#  -----------     ----    -------------------------------------------------------
#   29-Mar-2025     0.00    Added the Change Management
#   29-Mar-2025     0.01    Added the logging information
#   27-Jan-2026     0.02    refactoring the code to create a class for OracleFusionAccessManager
#   21-Jan-2026     0.03    Removing code smell
#   TODO:
#   1) Remove trailing spaces from the names
#   2) Add Role Assignment
#   3) Think about validating the csv file
#   4) There can be a case, where a user has role, but does not require the security context value.
#   In that case, we need to skip the security context value check.
#


import json
import logging
import os
import sys
from collections import defaultdict

import pandas
import requests
import urllib3
import yaml
from pythonjsonlogger.json import JsonFormatter

from common.utils import convert_dict, generate_basic_auth_token

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def setup_logging(log_level=logging.INFO):
    """Setup structured JSON logging for production observability"""
    root_logger = logging.getLogger()
    root_logger.handlers = []
    root_logger.setLevel(log_level)
    handler = logging.StreamHandler(sys.stdout)

    # FIX: Remove rename_fields, it's not working correctly
    formatter = jsonlogger.JsonFormatter( # type: ignore
        '%(asctime)s %(levelname)s %(name)s %(funcName)s %(message)s'
    )

    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

    return root_logger

# Module-level logger - DECLARE HERE, but don't call setup yet
logger = logging.getLogger(__name__)


class Config:
    # CSV column names
    CSV_USERNAME = "UserName"
    CSV_ROLE_NAME = "RoleNameCr"
    CSV_SECURITY_CONTEXT = "SecurityContext"
    CSV_SECURITY_VALUE = "SecurityContextValue"

    # Oracle API field names
    ORACLE_API_USER_FIELD = "Userrf"
    ORACLE_API_ROLE_FIELD = "Rolerf"
    ORACLE_API_SECURITY_CTX_FIELD = "SecurityContext"
    ORACLE_API_SECURITY_CTX_VAL_FIELD = "SecurityContextValue"

    # File names
    OUTPUT_FILE = "Output.csv"

    # API settings
    API_TIMEOUT = 30


class OracleFusionAccessManager:
    """Manages bulk data security role assignments in Oracle Fusion Cloud.

    Handles configuration loading, CSV processing, API communication,
    and role assignment verification against existing user access.

    Args:
        config_path: Path to YAML configuration file.
        file_name: Path to CSV file containing user-role mappings.
        allow_interactive: If True, prompts for credentials when config file is missing.
    """
    def __init__(self,
                 config_path,
                 file_name,
                 allow_interactive=False):
        logger.debug("Class initialized")
        logger.info("Loading configuration data")
        self.allow_interactive = allow_interactive
        self.config_data = self.load_config(config_path)
        self.file_name = file_name
        self.instance_code, self.instance_name, self.username, self.password = (
            self.config_data["instance_code"],
            self.config_data["instance_name"],
            self.config_data["username"],
            self.config_data["password"],
        )

        self.base_url: str = (
            f"https://{self.instance_code}-{self.instance_name}-saasfaprod1.fa.ocs.oraclecloud.com"
        )
        self.uri_path: str = "/fscmRestApi/resources/11.13.18.05/dataSecurities"
        self.assign_uri_path: str = "/fscmRestApi/resources/latest"
        logger.debug("Generating Token for the API call")
        self.token: str = generate_basic_auth_token(self.username, self.password)

    def load_config(self, config_path: str) -> dict:
        """Load Oracle Fusion connection settings from YAML config file.

        Args:
            config_path: Path to the YAML configuration file.

        Returns:
            Dictionary containing instance_code, instance_name, username, and password.

        Raises:
            FileNotFoundError: If config file is missing and interactive mode is disabled.
        """
        logger.debug(f"Loading config from {config_path}")
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f).get("oracle_fusion", {})
                config_data = {
                    key: config.get(key)
                    for key in [
                        "instance_code",
                        "instance_name",
                        "username",
                        "password",
                    ]
                }
            logger.debug("Config file loaded successfully.")
        except FileNotFoundError:
            if self.allow_interactive:
                logger.warning(
                    "Config.yaml File not Found. Please enter the details manually."
                )
                config_data = {}
                for key in ["instance_code", "instance_name", "username", "password"]:
                    config_data[key] = input(
                        f"Enter {key.replace('_', ' ').title()}: "
                    ).strip()
            else:
                logger.error("Config.yaml File not Found.")
                raise
        return config_data

    def read_csv(self) -> None:
        """Read and sort the user-role mapping CSV file.

        Raises:
            FileNotFoundError: If the CSV file does not exist.
        """
        logger.debug(f"Reading CSV file: {self.file_name}")
        try:
            self.df = pandas.read_csv(self.file_name, dtype={Config.CSV_USERNAME: str})
            self.df.sort_values(by=[Config.CSV_USERNAME], inplace=True)
            logger.info("CSV file read successfully.")
            return None
        except FileNotFoundError:
            logger.error(f"CSV file {self.file_name} not found.")
            raise

    def user_has_access(self,
                        data: dict,
                        user: str,
                        role: str,
                        security_context: str,
                        value: str) -> bool:
        """Check if a user already has a specific role and security context assigned.

        Args:
            data: Nested dictionary of existing user access from API.
            user: Username to check.
            role: Role name to check.
            security_context: Security context type (e.g., 'Business Unit').
            value: Security context value (e.g., 'USA').

        Returns:
            True if the user already has the exact access, False otherwise.
        """
        return (
            user in data
            and role in data[user]
            and security_context in data[user][role]
            and value in data[user][role][security_context]
        )

    def process_row(self) -> None:
        """Process each user from CSV, check existing access, and assign missing roles.

        Writes results to Output.csv with status for each user-role combination.
        """
        logger.info("Processing user data access")
        with open(Config.OUTPUT_FILE, "w", encoding="utf-8-sig") as file_obj:

            """Creating header for output file"""
            file_obj.writelines("UserName, RoleName, SecurityContext, Value, Status\n")

            list_of_roles = {}
            for username in self.df[Config.CSV_USERNAME].unique():
                reader = []

                logger.info(f"Fetching existing access for {username}")
                list_of_roles = self.collect_user_roles(username)
                logger.info(f"Assigning Data Access for {username}")
                for _index, row in self.df[self.df[Config.CSV_USERNAME] == username].iterrows():
                    uname = row[Config.CSV_USERNAME]
                    rolename = row[Config.CSV_ROLE_NAME]
                    security_context = row[Config.CSV_SECURITY_CONTEXT]
                    value = row[Config.CSV_SECURITY_VALUE]
                    if self.user_has_access(
                        list_of_roles, uname, rolename, security_context, value
                    ):
                        file_obj.writelines(
                            f"{uname}, {rolename}, {security_context}, {value}, Access already assigned\n"
                        )
                    else:
                        reader.append((uname, security_context, rolename, value))
                        file_obj.writelines(
                            f"{uname}, {rolename}, {security_context}, {value}, Value not assigned\n"
                        )
                if reader:
                    self._assign_and_log(reader,username)


    def _assign_and_log(self, reader: list,username:str) -> requests.Response | None:
        """Assign new data access and log the result.
        Args:
            reader: List of tuples containing (username, security_context, role, value).
            username: Username being processed (for logging).
        """
        logger.info(f"Assigning new access for {username}")
        result = self._assign_data_access(reader)
        if result and result.status_code == 200:
            logger.info(f"Data Access granted for {username}")
        else:
            logger.error(
                            f"Failed to assign access for {username}: {result.text if result else 'No response'}"
                        )


    def create_api_payload(self, reader: list) -> dict:
        """Create batch API payload for Oracle Fusion data security assignment.

        Args:
            reader: List of tuples containing (username, security_context, role, value).

        Returns:
            Dictionary formatted for Oracle Fusion batch REST API.
        """
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
                        "UserName": username,
                    },
                }
                for i, (
                    username,
                    Security_Context,
                    Role_NameCr,
                    security_value,
                ) in enumerate(reader)
            ]
        }
        return payload

    def _assign_data_access(self, reader: list) -> requests.Response | None:
        """Send batch POST request to assign data security roles.

        Args:
            reader: List of tuples containing (username, security_context, role, value).

        Returns:
            Response object on success, None on failure.
        """

        url = f"{self.base_url}{self.assign_uri_path}"

        headers = {
            "Content-Type": "application/vnd.oracle.adf.batch+json",
            "Authorization": self.token,
        }
        json_payload = json.dumps(self.create_api_payload(reader), indent=4)
        logger.info(f"Assigning data access for {len(reader)} records.")
        logger.debug(f"Payload: {json_payload}")
        try:
            response = requests.request(
                "POST",
                url,
                headers=headers,
                data=json_payload,
                verify=False,
                timeout=Config.API_TIMEOUT,
                stream=False,
            )
            logger.debug(f"POST request sent. Status Code: {response.status_code}")
            return response
        except Exception as e:
            logger.error(f"Failed to assign data access: {e}")
            logger.error(f"Payload: {json_payload}")
            return None

    def collect_user_roles(self, file_username: str) -> dict:
        """Fetch all existing role assignments for a user from Oracle Fusion API.

        Handles pagination automatically when the API returns multiple pages.

        Args:
            file_username: Username to query existing roles for.

        Returns:
            Nested dictionary of user's current role assignments.
        """
        has_more: bool = True
        running_total: int = 0
        list_of_roles = {}
        result = self.fetch_data_from_api(
            f"q={Config.ORACLE_API_USER_FIELD}={file_username}&offset={running_total}"
        )
        if result is None:
            logger.error(f"Failed to fetch data for user {file_username}")
            return {}
        list_of_roles = self._create_output_dict(result)
        running_total = running_total + result.json().get("count") + 1
        has_more = result.json().get("hasMore")
        while has_more:
            result = self.fetch_data_from_api(
                f"q={Config.ORACLE_API_USER_FIELD}={file_username}&offset={running_total}"
            )
            if result is None:
                logger.error(f"Failed to fetch data for user {file_username}")
                return {}

            has_more = result.json().get("hasMore", False)
            running_total += result.json().get("count", 0) + 1
            list_of_roles[file_username].update(
                self._create_output_dict(result)[file_username]
            )
        return convert_dict(list_of_roles)

    def fetch_data_from_api(self, query_para: str = "") -> requests.Response | None:
        """Make GET request to Oracle Fusion data securities API.

        Args:
            query_para: Query parameters to append to the API URL.

        Returns:
            Response object on success, None on failure.
        """

        query_para = (
            f"?totalResults=true&{query_para}" if query_para else "?totalResults=true"
        )
        url = f"{self.base_url}{self.uri_path}{query_para}"
        headers = {"Authorization": self.token}
        logger.info(f"Making GET request to {url}")
        logger.debug(f"Headers: {headers}")
        try:
            response = requests.request(
                "GET",
                url,
                headers=headers,
                data={},
                verify=False,
                timeout=Config.API_TIMEOUT,
                stream=False,
            )
            if response.status_code == 200:
                logger.info("API response received successfully.")
            else:
                logger.warning(
                    f"API returned status {response.status_code}: {response.text}"
                )
            return response
        except Exception as e:
            logger.error(f"Failed to fetch data: {e}")
            return None

    def _create_output_dict(self, response: requests.Response) -> dict:
        """Transform API response into nested user-role-context dictionary.

        Args:
            response: API response containing data security items.

        Returns:
            Nested dict structured as {user: {role: {context: [values]}}}.
        """
        logger.debug("Transforming API response into structured dictionary.")

        # Create nested dict structure: user -> role -> context -> [values]
        result = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

        try:
            items = response.json().get("items", [])
            for val in response.json().get("items"):
                user = val[Config.ORACLE_API_USER_FIELD]
                role = val[Config.ORACLE_API_ROLE_FIELD]
                context = val[Config.ORACLE_API_SECURITY_CTX_FIELD]
                contextvalue = val[Config.ORACLE_API_SECURITY_CTX_VAL_FIELD]
                result[user][role][context].append(contextvalue)

            logger.debug(f"Transformation successful. Processed {len(items)} items.")
        except Exception as e:
            logger.error(f"Error in processing API response: {e}")
        return result


if __name__ == "__main__":
    #logging.basicConfig(
    #    level=logging.INFO, format="%(asctime)s - %(name)s - %(funcName)s - %(levelname)s - %(message)s"
    #)
    logger = setup_logging(log_level=logging.INFO)

    logger.info(
        "Starting script execution.1",
        extra={
            'event': 'Start Script'
        }
    )

    # Get the directory where the current script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "config", "config.yaml")

    file_name = "User_Data_Access.csv"

    """Creating object of OracleFusionAccessManager class"""
    assign_role = OracleFusionAccessManager(
        config_path, file_name, allow_interactive=True
    )

    """Reading CSV file"""
    assign_role.read_csv()

    """Processing CSV file"""
    assign_role.process_row()
