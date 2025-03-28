import base64
from collections import defaultdict

def generate_basic_auth_token(username: str,
                              passowrd: str)->str:
    credentials : str =f"{username}:{passowrd}"    
    return f"Basic {base64.b64encode(credentials.encode()).decode()}"

def convert_dict(dd):
    if isinstance(dd,defaultdict):
        return {k:conver_dict(v) for k,v in dd.items()}
    return dd