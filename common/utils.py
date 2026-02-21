'''
Date            Ver     Description
-----------     ----    -------------------------------------------------------
29-Mar-2025     0.01    Added the Change Management
'''


import base64
from collections import defaultdict


def generate_basic_auth_token(username: str,
                              password: str)->str:
    """Generate a Base64-encoded Basic Authentication token.

    Args:
        username: Oracle Fusion service account username.
        password: Oracle Fusion service account password.

    Returns:
        Basic auth header value in format 'Basic <encoded_credentials>'.
    """
    credentials : str = f"{username}:{password}"
    return f"Basic {base64.b64encode(credentials.encode()).decode()}"

def convert_dict(nested_data: dict) -> dict:
    """Recursively convert nested defaultdicts to regular dicts.

    Args:
        nested_data: A defaultdict (possibly nested) to convert.

    Returns:
        A standard dict with all nested defaultdicts converted.
    """
    if isinstance(nested_data,defaultdict):
        return {k:convert_dict(v) for k,v in nested_data.items()}
    return nested_data
